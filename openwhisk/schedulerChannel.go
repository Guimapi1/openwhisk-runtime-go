/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openwhisk

// schedulerChannel.go implements the Go side of the dedicated runtime ->
// scheduler HTTP channel (CLAUDE.md §6.5, §6.6, §7.6; PLAYBOOK.md
// Phase 7's resolved open questions #2/#3). The runtime is always the
// one making the OUTBOUND call to SCHEDULER_URL/api/v1/energy/events,
// because the scheduler has a stable, known address while an ephemeral
// action container does not have one the scheduler could call back on.
//
// EXECUTION_PAUSED (postExecutionPaused): the call BLOCKS until the
// scheduler responds — that response body IS the RESUME_EXECUTION /
// KILL_EXECUTION command (§7.5 step 7's "attendre une commande explicite
// du scheduler"). This replaces the earlier design (phase 5) where a
// pauseEnabled=false kill's EXECUTION_KILLED payload was embedded
// directly in the /run HTTP response — that channel cannot carry a
// PAUSE, since /run's caller (OpenWhisk itself) is not the scheduler and
// cannot answer with a command.
//
// EXECUTION_KILLED (postExecutionKilled): fire-and-forget, never blocks
// the /run response on it (CLAUDE.md §3.1: no round-trip before an
// already-decided kill). Used for BOTH the pauseEnabled=false immediate
// kill and this phase's own pause-cycle kill fallback — cgroup.kill
// (killExecution) is the only kill path either way (open question #3).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

// schedulerURL returns the scheduler's base URL, overridable via
// SCHEDULER_URL (this repo's convention: env vars read directly where
// used, no centralized config.go on the Go side — see cgroupFreezer.go,
// energyMonitor.go).
func schedulerURL() string {
	if v := os.Getenv("SCHEDULER_URL"); v != "" {
		return v
	}
	return "http://localhost:5000"
}

func schedulerEventsEndpoint() string {
	return schedulerURL() + "/api/v1/energy/events"
}

// schedulerChannelTimeoutMarginMs reads SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS
// (default 2000ms): the safety margin added on top of the pause cycle's
// own max_pause_duration_ms when bounding the blocking EXECUTION_PAUSED
// call (see pausedEventTimeout) — covers network latency and the
// scheduler's own processing time around its internal deadline, so a
// legitimate-but-slightly-late scheduler decision is never mistaken for
// a network failure and turned into a spurious local kill.
func schedulerChannelTimeoutMarginMs() time.Duration {
	ms := 2000
	if v := os.Getenv("SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// pausedEventTimeout bounds the blocking EXECUTION_PAUSED call.
// maxPauseDurationMs is THIS pause cycle's own deadline (CLAUDE.md §4.7,
// as dispatched — or as last updated by a previous RESUME_EXECUTION,
// though V1 never changes it mid-trace).
// schedulerTransport est le POOL DE CONNEXIONS partage par tous les
// appels au scheduler. Un `http.Transport` porte le pool ; le `Client`
// qui l'enveloppe ne porte que le timeout. On partage donc le transport
// et on fabrique un client leger par appel — ce qui conserve la
// reutilisation de connexion SANS renoncer au timeout variable de
// pausedEventTimeout(), qui depend du max_pause_duration_ms du cycle.
//
// Pourquoi ce changement (mesure du 2026-09-14). Chaque appel creait son
// propre `http.Client`, donc son propre transport, donc une connexion
// TCP neuve fermee aussitot. Mesure a l'interieur du cluster, 40 appels
// par bras, meme endpoint en lecture seule :
//
//	connexion NEUVE a chaque appel   p50 = 9,115 ms
//	connexion REUTILISEE             p50 = 0,527 ms   -> facteur 17
//
// Rapporte au cout de commande mesure (`command_roundtrip_ns`, mediane
// 15,55 ms), dont la DECISION du scheduler ne represente que 0,88 ms :
// l'etablissement de connexion en constituait environ 55 %. §7.9 compte
// ce cout comme une metrique de premier ordre — il est donc reel, pas
// cosmetique.
var schedulerTransport = &http.Transport{
	// CLAUDE.md §0 décision 43 (a) : une connexion neuve vise l'adresse du
	// scheduler résolue hors du chemin critique (voir schedulerDialContext).
	DialContext:         schedulerDialContext,
	MaxIdleConns:        16,
	MaxIdleConnsPerHost: 8,
	IdleConnTimeout:     90 * time.Second,
}

// ---------------------------------------------------------------------
// CLAUDE.md §0 décision 43 — canal de pause : aucune résolution de nom
// entre le gel et la décision, et cause d'échec enregistrée.
//
// Mesuré en campagne 8 (job 4180123) : 44 gels sur 15 162 sans commande dans
// le délai de 2,5 s, tous sans connexion obtenue, alors que les 11 388
// autres connexions neuves sont établies en moins de 50 ms et qu'aucun des
// 3 730 signalements partis sur une connexion déjà ouverte n'échoue. Dans 43
// cas, le conteneur ne rejoint le scheduler que 5,01 à 5,02 s après le gel :
// la durée d'une tentative de résolution de nom. Le runtime s'adresse au
// scheduler par son nom de service, qu'il résolvait à chaque connexion
// neuve — donc aussi pendant un gel.
//
// (a) L'adresse est résolue au démarrage du conteneur, en arrière-plan, et
// gardée. Une connexion neuve la vise directement. Elle n'est résolue de
// nouveau qu'après un échec de connexion, en arrière-plan : jamais sur le
// chemin d'un signalement de gel. Sans adresse gardée (résolution de
// démarrage pas encore aboutie, ou adresse oubliée après un échec et pas
// encore résolue de nouveau), la résolution se fait sur place, faute de
// mieux ; sa durée est enregistrée.
// (c) Chaque appel dit ce qu'il a coûté et, s'il échoue, à quelle étape :
// résolution, connexion, délai de réponse, réponse illisible.
// ---------------------------------------------------------------------

// lookupHostFunc résout un nom en adresses. Variable : les tests y mettent
// un résolveur lent ou en échec.
var lookupHostFunc = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// positiveIntEnv reads a strictly positive integer from the environment,
// or returns def when the variable is unset, unparsable or not positive.
// Env read directly, per this repo's convention.
func positiveIntEnv(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			return parsed
		}
	}
	return def
}

// schedulerAddressResolveMaxAttempts reads
// SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS (default 8): how many times the
// background resolution of the scheduler address is attempted before giving
// up. Past that, the next new connection resolves the name in place.
func schedulerAddressResolveMaxAttempts() int {
	return positiveIntEnv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", 8)
}

// schedulerAddressResolveTimeout reads SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS
// (default 500): bound on ONE resolution attempt (resolveOnce). Deliberately
// far below the resolver's own 5 s wait for a lost query, so that a lost
// query costs one short attempt and the next one goes out. Measured on the
// cluster (2026-10-11, 357 container starts): 308 resolutions took 4.2 to
// 15.8 ms, the 49 others stalled 5.00 to 5.01 s — 47 of them in the single
// minute where 169 containers started.
func schedulerAddressResolveTimeout() time.Duration {
	return time.Duration(positiveIntEnv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", 500)) * time.Millisecond
}

// resolveOnce : une tentative de résolution de host, bornée par
// SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS. Rend la première adresse utilisable.
func resolveOnce(ctx context.Context, host string) (string, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, schedulerAddressResolveTimeout())
	defer cancel()
	ips, err := lookupHostFunc(attemptCtx, host)
	if err != nil {
		return "", err
	}
	if ip := pickIP(ips); ip != "" {
		return ip, nil
	}
	return "", fmt.Errorf("no address for %s", host)
}

// schedulerAddressResolveBackoffBase reads
// SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS (default 200): base of the
// exponential backoff between two background resolution attempts.
func schedulerAddressResolveBackoffBase() time.Duration {
	return time.Duration(positiveIntEnv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", 200)) * time.Millisecond
}

// schedulerAddressResolveBackoffMax reads
// SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS (default 5000): cap on that
// backoff.
func schedulerAddressResolveBackoffMax() time.Duration {
	return time.Duration(positiveIntEnv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", 5000)) * time.Millisecond
}

// schedulerDialer : dialer à valeurs par défaut, celui que http.Transport
// emploie quand DialContext n'est pas renseigné (c'était le cas avant la
// décision 43). L'ouverture d'une connexion reste bornée par le délai de la
// requête, comme avant.
var schedulerDialer net.Dialer

// addrCache : l'adresse gardée d'un « nom:port ».
type addrCache struct {
	mu        sync.Mutex
	hostport  string
	ipport    string
	resolving bool
}

var schedulerAddr addrCache

func (c *addrCache) get(hostport string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostport == hostport {
		return c.ipport
	}
	return ""
}

func (c *addrCache) set(hostport, ipport string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hostport, c.ipport = hostport, ipport
}

func (c *addrCache) forget(hostport string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostport == hostport {
		c.ipport = ""
	}
}

// resolveAsync résout hostport en arrière-plan et garde le résultat. Sans
// effet si une résolution est déjà en cours, ou si l'hôte est déjà une
// adresse. Nombre de tentatives borné : au-delà, la prochaine connexion
// résoudra sur place.
func (c *addrCache) resolveAsync(hostport string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || net.ParseIP(host) != nil {
		return
	}
	c.mu.Lock()
	if c.resolving {
		c.mu.Unlock()
		return
	}
	c.resolving = true
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.resolving = false
			c.mu.Unlock()
		}()
		maxAttempts := schedulerAddressResolveMaxAttempts()
		backoff, backoffMax := schedulerAddressResolveBackoffBase(), schedulerAddressResolveBackoffMax()
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			started := time.Now()
			ip, lookupErr := resolveOnce(context.Background(), host)
			if lookupErr == nil {
				c.set(hostport, net.JoinHostPort(ip, port))
				log.Printf("[pause] scheduler address resolved off the critical path: %s -> %s (%.1f ms, attempt %d)",
					hostport, ip, float64(time.Since(started).Microseconds())/1000.0, attempt)
				return
			}
			log.Printf("[pause] scheduler address resolution attempt %d/%d failed for %s: %v",
				attempt, maxAttempts, hostport, lookupErr)
			if attempt == maxAttempts {
				break // rien à attendre après la dernière tentative
			}
			time.Sleep(backoff)
			if backoff *= 2; backoff > backoffMax {
				backoff = backoffMax
			}
		}
	}()
}

// pickIP rend la première adresse IPv4, sinon la première adresse.
func pickIP(ips []string) string {
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// schedulerHostPort rend le « hôte:port » de SCHEDULER_URL, tel que le
// transport le demande à schedulerDialContext.
func schedulerHostPort() string {
	u, err := url.Parse(schedulerURL())
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// warmSchedulerAddress lance la résolution de l'adresse du scheduler hors du
// chemin critique. Appelée au démarrage du conteneur (NewActionProxy).
func warmSchedulerAddress() {
	if hostport := schedulerHostPort(); hostport != "" && schedulerAddr.get(hostport) == "" {
		schedulerAddr.resolveAsync(hostport)
	}
}

// schedulerDialContext ouvre une connexion vers le scheduler sans résolution
// de nom quand son adresse est gardée.
func schedulerDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	rec := connRecorderFrom(ctx)
	dialer := &schedulerDialer

	if ipport := schedulerAddr.get(addr); ipport != "" {
		rec.noteCachedAddr()
		rec.noteConnectStart()
		conn, err := dialer.DialContext(ctx, network, ipport)
		rec.noteConnectDone()
		if err != nil {
			// L'adresse gardée ne répond plus : on l'oublie et on la résout
			// de nouveau en arrière-plan — jamais ici, cet appel est
			// peut-être fait pendant un gel.
			schedulerAddr.forget(addr)
			schedulerAddr.resolveAsync(addr)
		}
		return conn, err
	}

	// Pas d'adresse gardée : résolution sur place, par tentatives courtes
	// (resolveOnce) enchaînées sans attente — cet appel est peut-être fait
	// pendant un gel, et une requête DNS perdue ne doit pas lui coûter les
	// 5 s du résolveur.
	target := addr
	if host, port, splitErr := net.SplitHostPort(addr); splitErr == nil && net.ParseIP(host) == nil {
		rec.noteResolveStart()
		var ip string
		var err error
		for attempt, maxAttempts := 1, schedulerAddressResolveMaxAttempts(); ; attempt++ {
			if ip, err = resolveOnce(ctx, host); err == nil || ctx.Err() != nil || attempt >= maxAttempts {
				break
			}
		}
		rec.noteResolveDone(err)
		if err != nil {
			return nil, &net.DNSError{Err: err.Error(), Name: host}
		}
		target = net.JoinHostPort(ip, port)
	}
	rec.noteConnectStart()
	conn, err := dialer.DialContext(ctx, network, target)
	rec.noteConnectDone()
	if err == nil && target != addr {
		schedulerAddr.set(addr, target)
	}
	return conn, err
}

// schedulerClient rend un client au timeout demande, adosse au pool
// partage ci-dessus.
func schedulerClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: schedulerTransport}
}

// schedulerConnTrace rend OBSERVABLE ce qui n'etait jusqu'ici qu'infere
// d'une mediane : la connexion TCP a-t-elle ete reutilisee, et combien de
// temps a coute son obtention.
//
// Raison d'etre. Le partage du transport puis le drainage du corps ont
// tous deux ete deployes sans effet mesurable sur `command_roundtrip_ns`,
// et rien ne permettait de distinguer « le correctif n'est pas dans
// l'image » de « le correctif est la mais la connexion n'est quand meme
// pas recyclee ». Un `strings` sur le binaire ne tranche pas : le
// drainage est un appel a io.Copy, il n'ajoute aucun symbole propre.
// httptrace.GotConn repond directement, par cycle de pause.
type schedulerConnTrace struct {
	// Reused : net/http a servi la requete sur une connexion deja
	// etablie. C'est le critere exact que le transport partage + le
	// drainage visent a rendre vrai a partir du 2e cycle d'un meme
	// conteneur.
	Reused bool
	// SetupNs : debut de la requete -> connexion obtenue. Proche de zero
	// sur une connexion recyclee, de l'ordre de plusieurs ms sinon.
	SetupNs int64

	// CLAUDE.md §0 décision 43 (c).
	// DNSNs : durée de la résolution de nom faite PENDANT cet appel ; zéro
	// s'il n'y en a pas eu (connexion réutilisée, ou adresse gardée).
	DNSNs int64
	// ConnectNs : durée d'ouverture de la connexion TCP ; zéro sur une
	// connexion réutilisée.
	ConnectNs int64
	// CachedAddr : la connexion neuve visait l'adresse gardée.
	CachedAddr bool
	// Failure : cause de l'échec de l'appel, vide s'il a abouti.
	// resolve | connect | timeout | unreadable_response.
	Failure string
}

// Causes d'échec du canal de pause (§0 décision 43 (c)).
const (
	channelFailureResolve    = "resolve"
	channelFailureConnect    = "connect"
	channelFailureTimeout    = "timeout"
	channelFailureUnreadable = "unreadable_response"
)

// connRecorder remplit un schedulerConnTrace pendant un appel. Verrou et
// clôture : depuis Go 1.23, l'ouverture d'une connexion CONTINUE en
// arrière-plan après l'expiration de la requête qui l'a demandée ; ses
// rappels ne doivent plus rien écrire une fois l'appel revenu.
type connRecorder struct {
	mu               sync.Mutex
	closed           bool
	start            time.Time
	trace            schedulerConnTrace
	resolveStartedAt time.Time // zéro : aucune résolution pendant cet appel
	resolveEnded     bool
	resolveOK        bool
	connectStartedAt time.Time // zéro : aucune ouverture de connexion
	connectEnded     bool
	gotConn          bool
}

type connRecorderKey struct{}

// connRecorderFrom rend l'enregistreur de l'appel en cours, ou nil : toutes
// ses méthodes acceptent un récepteur nil.
func connRecorderFrom(ctx context.Context) *connRecorder {
	rec, _ := ctx.Value(connRecorderKey{}).(*connRecorder)
	return rec
}

func (r *connRecorder) update(fn func()) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		fn()
	}
}

func (r *connRecorder) noteCachedAddr()   { r.update(func() { r.trace.CachedAddr = true }) }
func (r *connRecorder) noteResolveStart() { r.update(func() { r.resolveStartedAt = time.Now() }) }
func (r *connRecorder) noteConnectStart() { r.update(func() { r.connectStartedAt = time.Now() }) }

func (r *connRecorder) noteResolveDone(err error) {
	r.update(func() {
		r.trace.DNSNs = time.Since(r.resolveStartedAt).Nanoseconds()
		r.resolveEnded, r.resolveOK = true, err == nil
	})
}

func (r *connRecorder) noteConnectDone() {
	r.update(func() {
		r.trace.ConnectNs = time.Since(r.connectStartedAt).Nanoseconds()
		r.connectEnded = true
	})
}

func (r *connRecorder) noteGotConn(reused bool) {
	r.update(func() {
		r.gotConn = true
		r.trace.Reused = reused
		r.trace.SetupNs = time.Since(r.start).Nanoseconds()
	})
}

// finish clôt l'enregistrement et rend la trace. callErr est l'erreur de
// l'appel HTTP ; unreadable dit que la réponse est arrivée mais n'a pas pu
// être décodée.
func (r *connRecorder) finish(callErr error, unreadable bool) schedulerConnTrace {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	// Une résolution ou une ouverture de connexion encore en cours quand
	// l'appel revient (délai expiré) : sa durée est le temps déjà passé.
	if !r.resolveStartedAt.IsZero() && !r.resolveEnded {
		r.trace.DNSNs = time.Since(r.resolveStartedAt).Nanoseconds()
	}
	if !r.connectStartedAt.IsZero() && !r.connectEnded {
		r.trace.ConnectNs = time.Since(r.connectStartedAt).Nanoseconds()
	}
	switch {
	case unreadable:
		r.trace.Failure = channelFailureUnreadable
	case callErr == nil:
	case !r.resolveStartedAt.IsZero() && !r.resolveOK:
		// Résolution en échec, ou encore en cours quand le délai a expiré.
		r.trace.Failure = channelFailureResolve
	case !r.gotConn:
		r.trace.Failure = channelFailureConnect
	case isTimeout(callErr):
		// Connexion obtenue, requête partie : aucune réponse dans le délai.
		r.trace.Failure = channelFailureTimeout
	default:
		// Connexion perdue pendant l'échange.
		r.trace.Failure = channelFailureConnect
	}
	return r.trace
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// traceRequest habille une requete d'un enregistreur de connexion.
func traceRequest(req *http.Request, rec *connRecorder) *http.Request {
	rec.start = time.Now()
	ctx := context.WithValue(req.Context(), connRecorderKey{}, rec)
	return req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { rec.noteGotConn(info.Reused) },
	}))
}

func pausedEventTimeout(maxPauseDurationMs int64) time.Duration {
	if maxPauseDurationMs < 0 {
		maxPauseDurationMs = 0
	}
	return time.Duration(maxPauseDurationMs)*time.Millisecond + schedulerChannelTimeoutMarginMs()
}

// ExecutionPausedEvent is CLAUDE.md §7.6's EXECUTION_PAUSED event shape.
type ExecutionPausedEvent struct {
	Event            string  `json:"event"`
	TraceID          string  `json:"trace_id"`
	ReservationID    string  `json:"reservation_id"`
	PauseID          string  `json:"pause_id"`
	ActionName       string  `json:"action_name"`
	ExecutionPhase   string  `json:"execution_phase"`
	EnergyConsumedJ  float64 `json:"energy_consumed_j"`
	PauseRequestedAt float64 `json:"pause_requested_at"`
	PauseEffectiveAt float64 `json:"pause_effective_at"`
	FreezeLatencyMs  float64 `json:"freeze_latency_ms"`
}

// SchedulerCommand is CLAUDE.md §6.6's RESUME_EXECUTION / KILL_EXECUTION
// command shape (the union of both; only the fields relevant to
// Command are populated by the scheduler).
type SchedulerCommand struct {
	Command                string  `json:"command"`
	TraceID                string  `json:"trace_id"`
	ReservationID          string  `json:"reservation_id"`
	PauseID                string  `json:"pause_id"`
	NewExecutionThresholdJ float64 `json:"new_execution_threshold_j,omitempty"`
	Reason                 string  `json:"reason,omitempty"`
}

// newPauseID generates a unique pause_id (CLAUDE.md §2). Uses
// crypto/rand directly rather than pulling in a UUID dependency (this
// module pins its dependency set — see go.mod, testify v1.3.0) — 16
// random bytes give a collision probability negligible for this
// process's lifetime.
func newPauseID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is exceedingly rare (would indicate a
		// broken kernel entropy source); degrade to a timestamp-based ID
		// rather than aborting the whole pause cycle over it.
		log.Printf("[pause] crypto/rand failed, falling back to a timestamp-based pause_id: %v", err)
		return fmt.Sprintf("pause-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("pause-%x", buf)
}

// postExecutionPaused sends EXECUTION_PAUSED and BLOCKS for the
// scheduler's decision (§7.5 step 7). A non-nil error means the
// scheduler could not be reached or answered with something
// undecodable — the caller (energyMonitor.go's runPauseCycle) treats
// that as a reason to kill locally: resuming without ANY confirmed
// command would break CLAUDE.md §4.3's invariant
// (resume_allowed(pause_id) => extension_success(pause_id)), and this
// runtime has no way to satisfy that invariant if it cannot even reach
// the scheduler.
func postExecutionPaused(event ExecutionPausedEvent, maxPauseDurationMs int64) (*SchedulerCommand, schedulerConnTrace, error) {
	rec := &connRecorder{}

	body, err := json.Marshal(event)
	if err != nil {
		return nil, rec.finish(nil, false), fmt.Errorf("marshal EXECUTION_PAUSED event: %w", err)
	}

	client := schedulerClient(pausedEventTimeout(maxPauseDurationMs))
	req, err := http.NewRequest(http.MethodPost, schedulerEventsEndpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, rec.finish(nil, false), fmt.Errorf("build EXECUTION_PAUSED request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(traceRequest(req, rec))
	if err != nil {
		return nil, rec.finish(err, false), fmt.Errorf("POST EXECUTION_PAUSED: %w", err)
	}
	// Le corps doit etre DRAINE avant d'etre ferme, sinon la connexion
	// n'est pas rendue au pool et le transport partage ne sert a rien.
	//
	// Constate par la mesure (2026-09-14) : apres avoir partage le
	// transport, le cout de commande n'avait PAS baisse — 17,4 ms de
	// mediane contre 15,6 avant, et aucune decroissance entre trois
	// cycles servis par le MEME conteneur (19,6 -> 18,1 -> 17,1 ms, dont
	// deux a 42 s d'ecart, donc dans la fenetre IdleConnTimeout de 90 s).
	// Les symboles `schedulerClient`/`schedulerTransport` etaient pourtant
	// bien presents dans le binaire deploye — verifie par `strings` dans
	// le conteneur d'action.
	//
	// La cause est une exigence du `net/http` de Go : une connexion n'est
	// reutilisable que si le corps de la reponse a ete lu jusqu'a EOF
	// PUIS ferme. `json.Decoder.Decode` s'arrete a la fin de la valeur
	// JSON et peut laisser des octets (un saut de ligne suffit), ce qui
	// fait fermer la connexion au lieu de la recycler.
	//
	// Partager le transport etait donc NECESSAIRE mais PAS SUFFISANT.
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	var command SchedulerCommand
	if err := json.NewDecoder(resp.Body).Decode(&command); err != nil {
		// Délai expiré pendant la lecture du corps : c'est un délai, pas une
		// réponse illisible.
		if isTimeout(err) {
			return nil, rec.finish(err, false), fmt.Errorf("read scheduler command: %w", err)
		}
		return nil, rec.finish(err, true), fmt.Errorf("decode scheduler command: %w", err)
	}
	return &command, rec.finish(nil, false), nil
}

// executionKilledMaxAttempts reads EXECUTION_KILLED_MAX_ATTEMPTS
// (default 5): how many times EXECUTION_KILLED delivery is attempted
// before giving up. Env read directly, per this repo's convention.
func executionKilledMaxAttempts() int {
	n := 5
	if v := os.Getenv("EXECUTION_KILLED_MAX_ATTEMPTS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	return n
}

// executionKilledBackoffBase reads EXECUTION_KILLED_RETRY_BACKOFF_BASE_MS
// (default 200): base of the exponential backoff between two delivery
// attempts (base * 2^attempt).
func executionKilledBackoffBase() time.Duration {
	ms := 200
	if v := os.Getenv("EXECUTION_KILLED_RETRY_BACKOFF_BASE_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// logSafetyKilledUndelivered emits a critical structured [safety] event
// when EXECUTION_KILLED could not be delivered at all. Same JSON shape as
// energyMonitor.go's own [safety] events.
//
// This is the signal that was missing entirely. A lost delivery leaves the
// scheduler-side reservation open forever (nothing else ever settles it,
// CLAUDE.md §6.9/§11), and the ONLY previous trace of it was a plain log
// line — invisible in practice, since the logs of a container whose
// activation has already ended do not reach the invoker.
func logSafetyKilledUndelivered(event ExecutionKilledEvent, attempts int, lastErr string) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":          "EXECUTION_KILLED_UNDELIVERED",
		"severity":       "critical",
		"trace_id":       event.TraceID,
		"reservation_id": event.ReservationID,
		"action_name":    event.ActionName,
		"attempts":       attempts,
		"last_error":     lastErr,
		"detail": "EXECUTION_KILLED could not be delivered to the scheduler. " +
			"Its reservation stays open (CLAUDE.md §11: no terminal status " +
			"without runtime confirmation) and will only be released by an " +
			"explicit reconciliation or a scheduler restart.",
	})
	if err != nil {
		log.Printf("[safety] EXECUTION_KILLED undelivered for trace=%s (marshal failed: %v)", event.TraceID, err)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// postExecutionKilled delivers EXECUTION_KILLED to the scheduler, with
// bounded retries and an explicit status-code check.
//
// It stays OFF the /run response path — its only caller invokes it as
// `go postExecutionKilled(event)` — so none of this ever delays the
// response (CLAUDE.md §3.1).
//
// Why retrying is legitimate here, contrary to what this function's
// previous comment claimed ("retrying here would reintroduce exactly the
// round-trip §3.1 forbids"): §3.1 forbids a round-trip BEFORE the kill,
// because nothing would stop consumption while the runtime waits for an
// answer. That reasoning does not apply once the process is already dead
// — by this point killExecution() has run and the action burns nothing.
// Retrying costs no energy and blocks no response; the earlier reading
// conflated two different round-trips.
//
// What the previous single fire-and-forget attempt cost, measured on
// cluster (LIMITE_KILL_NON_CONFIRME.md, 2026-09-07): under s05's
// saturation the scheduler serialises several blocking EXECUTION_PAUSED
// calls, so a 5 s window is plausibly exceeded; a single failed POST then
// orphaned the reservation for good — 4 runs out of 4 left an unsettled
// trace, and the accumulation eventually drove the invoker Unresponsive.
//
// Delivery is idempotent scheduler-side: a re-delivered event whose
// reservation is already terminal is handled gracefully (§0 decision 28),
// so a retry after an ambiguous failure is safe.
func postExecutionKilled(event ExecutionKilledEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("[energy_monitor] failed to marshal EXECUTION_KILLED event for the scheduler channel: %v", err)
		return
	}

	maxAttempts := executionKilledMaxAttempts()
	base := executionKilledBackoffBase()
	client := schedulerClient(5 * time.Second)
	lastErr := "none"

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(base * time.Duration(1<<uint(attempt-1)))
		}
		resp, err := client.Post(schedulerEventsEndpoint(), "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err.Error()
			log.Printf(
				"[energy_monitor] EXECUTION_KILLED delivery attempt %d/%d failed for trace=%s: %v",
				attempt+1, maxAttempts, event.TraceID, err,
			)
			continue
		}
		status := resp.StatusCode
		// Meme exigence que pour postExecutionPaused : drainer avant de
		// fermer, sinon la connexion n'est pas rendue au pool partage.
		// Ici le corps n'est meme pas lu (seul le statut compte), donc
		// sans ce drainage la connexion etait systematiquement jetee.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if status >= 200 && status < 300 {
			if attempt > 0 {
				log.Printf(
					"[energy_monitor] EXECUTION_KILLED delivered for trace=%s on attempt %d/%d",
					event.TraceID, attempt+1, maxAttempts,
				)
			}
			return
		}

		lastErr = fmt.Sprintf("HTTP %d", status)
		// 4xx is the scheduler REFUSING this payload — retrying an
		// identical body cannot change that answer, and would only delay
		// the [safety] event that says so.
		if status >= 400 && status < 500 {
			log.Printf(
				"[energy_monitor] EXECUTION_KILLED refused for trace=%s: HTTP %d — not retried",
				event.TraceID, status,
			)
			break
		}
		log.Printf(
			"[energy_monitor] EXECUTION_KILLED delivery attempt %d/%d for trace=%s: HTTP %d",
			attempt+1, maxAttempts, event.TraceID, status,
		)
	}

	logSafetyKilledUndelivered(event, maxAttempts, lastErr)
}
