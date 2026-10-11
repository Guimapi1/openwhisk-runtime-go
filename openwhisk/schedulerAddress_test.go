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

// CLAUDE.md §0 décision 43 : aucune résolution de nom entre le gel et la
// décision, et cause d'un échec du canal enregistrée.
//
// Le faux scheduler écoute sur 127.0.0.1 ; SCHEDULER_URL le désigne par un
// NOM (scheduler.test), que seul le faux résolveur du test sait résoudre —
// lentement ou pas du tout, à la demande.

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const schedulerTestHost = "scheduler.test"

// fakeResolver remplace lookupHostFunc : compte ses appels, attend `delay`,
// puis rend `ip` ou `err`.
type fakeResolver struct {
	mu    sync.Mutex
	delay time.Duration
	ip    string
	err   error
	calls int64
	// lostFirst : les N premiers appels ne reçoivent jamais de réponse (une
	// requête DNS perdue) ; ils ne reviennent qu'à l'annulation de leur contexte.
	lostFirst int64
}

func (r *fakeResolver) set(delay time.Duration, ip string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delay, r.ip, r.err = delay, ip, err
}

func (r *fakeResolver) lookup(ctx context.Context, host string) ([]string, error) {
	if n := atomic.AddInt64(&r.calls, 1); n <= atomic.LoadInt64(&r.lostFirst) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.mu.Lock()
	delay, ip, err := r.delay, r.ip, r.err
	r.mu.Unlock()
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return []string{ip}, nil
}

func (r *fakeResolver) count() int64 { return atomic.LoadInt64(&r.calls) }

// useNamedScheduler : SCHEDULER_URL désigne le faux scheduler par son nom ;
// rend le « nom:port » que le transport demandera et le faux résolveur.
// L'état partagé du canal (adresse gardée, connexions en attente) repart de
// zéro et est remis en l'état à la fin du test.
func useNamedScheduler(t *testing.T, serverURL string) (string, *fakeResolver) {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)
	hostport := net.JoinHostPort(schedulerTestHost, u.Port())
	t.Setenv("SCHEDULER_URL", "http://"+hostport)

	resolver := &fakeResolver{ip: "127.0.0.1"}
	previous := lookupHostFunc
	lookupHostFunc = resolver.lookup
	schedulerAddr.set("", "")
	schedulerTransport.CloseIdleConnections()
	t.Cleanup(func() {
		lookupHostFunc = previous
		schedulerAddr.set("", "")
		schedulerTransport.CloseIdleConnections()
	})
	return hostport, resolver
}

func pausedEventFor(traceID string) ExecutionPausedEvent {
	return ExecutionPausedEvent{Event: "EXECUTION_PAUSED", TraceID: traceID, ReservationID: traceID, PauseID: "pause-" + traceID}
}

// (a) L'adresse est résolue au démarrage, en arrière-plan. Un signalement de
// gel envoyé ensuite ne consulte plus le résolveur, même devenu très lent :
// c'est la situation des 44 gels perdus de la campagne 8.
func TestSchedulerAddress_ResolvedAtStartup_APauseEventNeverWaitsForTheResolver(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)

	warmSchedulerAddress()
	waitFor(t, 2*time.Second, "adresse du scheduler gardée", func() bool { return schedulerAddr.get(hostport) != "" })
	require.Equal(t, int64(1), resolver.count())

	resolver.set(5*time.Second, "127.0.0.1", nil) // le résolveur met maintenant 5 s à répondre

	started := time.Now()
	command, trace, err := postExecutionPaused(pausedEventFor("warm"), 500)
	elapsed := time.Since(started)

	require.NoError(t, err)
	assert.Equal(t, "RESUME_EXECUTION", command.Command)
	assert.True(t, elapsed < time.Second, "le signalement ne doit pas attendre le résolveur : %s", elapsed)
	assert.Equal(t, int64(1), resolver.count(), "aucune résolution pendant le signalement")
	assert.True(t, trace.CachedAddr, "connexion ouverte vers l'adresse gardée")
	assert.False(t, trace.Reused)
	assert.Equal(t, int64(0), trace.DNSNs)
	assert.True(t, trace.ConnectNs > 0)
	assert.Equal(t, "", trace.Failure)
}

// Le démarrage ne bloque pas sur le résolveur, et le conteneur n'attend pas
// l'adresse pour servir.
func TestSchedulerAddress_WarmUpDoesNotBlockTheCaller(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "2000") // un résolveur lent, pas une requête perdue
	resolver.set(400*time.Millisecond, "127.0.0.1", nil)

	started := time.Now()
	warmSchedulerAddress()
	warmSchedulerAddress() // une seule résolution à la fois
	assert.True(t, time.Since(started) < 100*time.Millisecond)
	assert.Equal(t, "", schedulerAddr.get(hostport), "pas encore résolue")

	waitFor(t, 3*time.Second, "adresse gardée après la résolution lente", func() bool { return schedulerAddr.get(hostport) != "" })
	assert.Equal(t, int64(1), resolver.count())
}

// Sans adresse gardée, la résolution se fait sur place, faute de mieux. Si
// elle ne revient pas dans le délai du canal, la cause enregistrée est la
// résolution, avec le temps qu'elle avait déjà pris.
func TestSchedulerAddress_ColdCache_ASlowResolutionIsRecordedAsTheCause(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	t.Setenv("SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS", "100")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "2000") // un résolveur lent, pas une requête perdue
	resolver.set(700*time.Millisecond, "127.0.0.1", nil)

	started := time.Now()
	_, trace, err := postExecutionPaused(pausedEventFor("cold"), 100) // délai du canal : 200 ms
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.True(t, elapsed < 600*time.Millisecond, "l'appel revient à son délai, pas à celui du résolveur : %s", elapsed)
	assert.Equal(t, channelFailureResolve, trace.Failure)
	assert.False(t, trace.CachedAddr)
	assert.True(t, trace.DNSNs >= (150*time.Millisecond).Nanoseconds(), "durée de résolution déjà écoulée : %d ns", trace.DNSNs)
	assert.Empty(t, fs.getPausedEvents(), "le signalement n'est jamais parti")

	// La résolution lancée par cet appel aboutit ensuite en arrière-plan :
	// l'adresse est gardée, le signalement suivant part sans attendre.
	waitFor(t, 3*time.Second, "adresse gardée après coup", func() bool { return schedulerAddr.get(hostport) != "" })
	resolver.set(5*time.Second, "127.0.0.1", nil)
	_, trace, err = postExecutionPaused(pausedEventFor("cold-2"), 100)
	require.NoError(t, err)
	assert.Equal(t, "", trace.Failure)
	assert.Equal(t, int64(0), trace.DNSNs)
}

func TestSchedulerAddress_ColdCache_AFailedResolutionIsRecordedAsTheCause(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	_, resolver := useNamedScheduler(t, fs.server.URL)
	resolver.set(0, "", errors.New("no such host"))

	_, trace, err := postExecutionPaused(pausedEventFor("nxdomain"), 500)

	require.Error(t, err)
	assert.Equal(t, channelFailureResolve, trace.Failure)
}

// L'adresse gardée ne répond plus : l'appel échoue vite, à la connexion.
// L'adresse est oubliée et résolue de nouveau EN ARRIÈRE-PLAN — pas pendant
// l'appel, qui est peut-être un signalement de gel.
func TestSchedulerAddress_CachedAddressRefused_FailsFastAndReResolvesInTheBackground(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)

	// Une adresse où plus rien n'écoute.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := dead.Addr().String()
	require.NoError(t, dead.Close())
	schedulerAddr.set(hostport, deadAddr)
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "2000") // un résolveur lent, pas une requête perdue
	resolver.set(300*time.Millisecond, "127.0.0.1", nil)

	started := time.Now()
	_, trace, err := postExecutionPaused(pausedEventFor("refused"), 2000)
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.Equal(t, channelFailureConnect, trace.Failure)
	assert.True(t, trace.CachedAddr)
	assert.Equal(t, int64(0), trace.DNSNs, "aucune résolution pendant l'appel")
	assert.True(t, elapsed < 250*time.Millisecond, "l'appel n'attend pas la nouvelle résolution : %s", elapsed)
	assert.Equal(t, "", schedulerAddr.get(hostport), "l'adresse qui ne répond plus est oubliée")

	waitFor(t, 3*time.Second, "nouvelle adresse gardée", func() bool { return schedulerAddr.get(hostport) != "" })
	assert.NotEqual(t, deadAddr, schedulerAddr.get(hostport))
	command, trace, err := postExecutionPaused(pausedEventFor("refused-2"), 2000)
	require.NoError(t, err)
	assert.Equal(t, "RESUME_EXECUTION", command.Command)
	assert.Equal(t, "", trace.Failure)
}

// (c) Connexion obtenue, requête partie, aucune réponse dans le délai.
func TestSchedulerChannel_NoAnswerWithinTheDeadline_IsRecordedAsATimeout(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	useNamedScheduler(t, fs.server.URL)
	t.Setenv("SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS", "100")
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		time.Sleep(600 * time.Millisecond)
		return SchedulerCommand{Command: "RESUME_EXECUTION", PauseID: ev.PauseID}
	})

	_, trace, err := postExecutionPaused(pausedEventFor("silent"), 100)

	require.Error(t, err)
	assert.Equal(t, channelFailureTimeout, trace.Failure)
	assert.True(t, trace.ConnectNs > 0, "la connexion, elle, a été obtenue")
}

// (c) Une réponse arrive, mais ce n'est pas une commande.
func TestSchedulerChannel_AnAnswerThatIsNotACommand_IsRecordedAsUnreadable(t *testing.T) {
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = ioutil.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	}))
	t.Cleanup(garbage.Close)
	useNamedScheduler(t, garbage.URL)

	_, trace, err := postExecutionPaused(pausedEventFor("garbage"), 500)

	require.Error(t, err)
	assert.Equal(t, channelFailureUnreadable, trace.Failure)
}

// Une connexion déjà ouverte : ni résolution ni ouverture de connexion.
func TestSchedulerChannel_AReusedConnectionNeedsNeitherResolutionNorConnect(t *testing.T) {
	fs := newFakeSchedulerServer(t)
	_, resolver := useNamedScheduler(t, fs.server.URL)

	_, first, err := postExecutionPaused(pausedEventFor("first"), 500)
	require.NoError(t, err)
	assert.False(t, first.Reused)
	assert.True(t, first.DNSNs > 0 || resolver.count() == 1, "premier appel à froid : résolution sur place")

	_, second, err := postExecutionPaused(pausedEventFor("second"), 500)
	require.NoError(t, err)
	assert.True(t, second.Reused)
	assert.Equal(t, int64(0), second.DNSNs)
	assert.Equal(t, int64(0), second.ConnectNs)
	assert.False(t, second.CachedAddr, "aucune connexion neuve : l'adresse gardée n'a pas servi")
	assert.Equal(t, int64(1), resolver.count())
}

// Une adresse littérale dans SCHEDULER_URL : rien à résoudre, rien à garder.
func TestSchedulerAddress_LiteralAddressIsNeverResolved(t *testing.T) {
	fs := newFakeSchedulerServer(t) // SCHEDULER_URL = http://127.0.0.1:port
	resolver := &fakeResolver{ip: "127.0.0.1"}
	previous := lookupHostFunc
	lookupHostFunc = resolver.lookup
	schedulerTransport.CloseIdleConnections()
	t.Cleanup(func() { lookupHostFunc = previous })

	warmSchedulerAddress()
	_, trace, err := postExecutionPaused(pausedEventFor("literal"), 500)

	require.NoError(t, err)
	assert.Equal(t, int64(0), resolver.count())
	assert.Equal(t, int64(0), trace.DNSNs)
	assert.False(t, trace.CachedAddr)
	assert.NotEmpty(t, fs.getPausedEvents())
}

// (c) De bout en bout : le cycle de pause envoyé au collecteur porte la
// cause de l'échec du canal — lisible dans les données, sans le journal du
// conteneur. Le scheduler ne répond pas : l'étape, tuable, est tuée sur
// place (PAUSE_CHANNEL_FAILED).
func TestRunHandler_PauseChannelFailure_CauseReachesTheCollector(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	t.Setenv("SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS", "100")
	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)
	fs := newFakeSchedulerServer(t)
	hostport, _ := useNamedScheduler(t, fs.server.URL)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		time.Sleep(700 * time.Millisecond) // plus long que le délai du canal (100 + 100 ms)
		return SchedulerCommand{Command: "RESUME_EXECUTION", PauseID: ev.PauseID}
	})

	os.RemoveAll("./action/pause_channel_cause")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_channel_cause", "", logf, logf) // résout l'adresse au démarrage
	waitFor(t, 2*time.Second, "adresse du scheduler gardée au démarrage", func() bool { return schedulerAddr.get(hostport) != "" })
	script := []byte("#!/bin/sh\nwhile read a; do sleep 30; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	ts := httptest.NewServer(ap)
	defer ts.Close()

	body := `{"value": {"energy_trace_id": "trace-cause", "energy_reservation_id": "trace-cause",
		"energy_execution_phase": "forward", "energy_execution_threshold_j": 1.0, "energy_consumed_before_j": 1.0,
		"energy_pause_enabled": true, "energy_pause_mode": "CGROUP_FREEZE", "energy_max_pause_duration_ms": 100,
		"energy_max_pause_count": 1, "energy_interruption_class": {"action": "KILL_SAFE"}}, "action_name": "action"}`
	_, status, err := doPost(ts.URL+"/run", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	payloads := collector.runPayloads()
	require.Len(t, payloads, 1)
	require.NotNil(t, payloads[0].Lifecycle)
	assert.Equal(t, "PAUSE_CHANNEL_FAILED", payloads[0].Lifecycle.KillCause)
	require.Len(t, payloads[0].Lifecycle.Cycles, 1)
	cycle := payloads[0].Lifecycle.Cycles[0]
	assert.Equal(t, "killed", cycle.Outcome)
	require.NotNil(t, cycle.CPUUsecWhileFrozen, "kill décidé par le runtime après un gel : le contrôle du gel est relevé avant le kill")
	assert.True(t, cycle.ChannelTraced, "le runtime déclare qu'il mesure le canal : le collecteur n'écrit ces champs qu'à cette condition")
	assert.Equal(t, channelFailureTimeout, cycle.ChannelFailure)
	assert.True(t, cycle.ChannelCachedAddr, "connexion vers l'adresse résolue au démarrage")
	assert.Equal(t, int64(0), cycle.ChannelDNSNs, "aucune résolution de nom pendant le gel")
	assert.True(t, cycle.ChannelConnectNs > 0)
}

// addrResolving dit si une résolution en arrière-plan est en cours.
func addrResolving() bool {
	schedulerAddr.mu.Lock()
	defer schedulerAddr.mu.Unlock()
	return schedulerAddr.resolving
}

// CLAUDE.md §11 : les réglages de la résolution en arrière-plan sont des
// variables d'environnement. Une valeur absente, illisible ou non positive
// laisse le défaut.
func TestSchedulerAddressSettings_DefaultsOverridesAndInvalidValues(t *testing.T) {
	for _, name := range []string{
		"SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS",
		"SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS",
	} {
		t.Setenv(name, "")
	}
	assert.Equal(t, 8, schedulerAddressResolveMaxAttempts())
	assert.Equal(t, 500*time.Millisecond, schedulerAddressResolveTimeout())
	assert.Equal(t, 200*time.Millisecond, schedulerAddressResolveBackoffBase())
	assert.Equal(t, 5*time.Second, schedulerAddressResolveBackoffMax())

	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "3")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "1500")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "50")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", "700")
	assert.Equal(t, 3, schedulerAddressResolveMaxAttempts())
	assert.Equal(t, 1500*time.Millisecond, schedulerAddressResolveTimeout())
	assert.Equal(t, 50*time.Millisecond, schedulerAddressResolveBackoffBase())
	assert.Equal(t, 700*time.Millisecond, schedulerAddressResolveBackoffMax())

	for _, invalid := range []string{"0", "-4", "abc", "1.5"} {
		t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", invalid)
		t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", invalid)
		t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", invalid)
		t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", invalid)
		assert.Equal(t, 8, schedulerAddressResolveMaxAttempts(), "valeur %q", invalid)
		assert.Equal(t, 500*time.Millisecond, schedulerAddressResolveTimeout(), "valeur %q", invalid)
		assert.Equal(t, 200*time.Millisecond, schedulerAddressResolveBackoffBase(), "valeur %q", invalid)
		assert.Equal(t, 5*time.Second, schedulerAddressResolveBackoffMax(), "valeur %q", invalid)
	}
}

// La résolution en arrière-plan s'arrête après le nombre de tentatives
// réglé, sans adresse gardée. La connexion suivante résout alors le nom sur
// place, et cette résolution se lit dans la trace de l'appel.
func TestSchedulerAddress_BackgroundResolutionGivesUpAfterTheConfiguredAttempts(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "3")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "1")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", "2")
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	resolver.set(0, "", errors.New("no such host"))

	warmSchedulerAddress()
	waitFor(t, 2*time.Second, "résolution en arrière-plan abandonnée", func() bool {
		return resolver.count() >= 3 && !addrResolving()
	})
	time.Sleep(50 * time.Millisecond) // aucune tentative de plus ne doit suivre
	assert.Equal(t, int64(3), resolver.count(), "nombre de tentatives = SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS")
	assert.Equal(t, "", schedulerAddr.get(hostport), "aucune adresse gardée après l'abandon")

	resolver.set(0, "127.0.0.1", nil) // le résolveur répond de nouveau
	command, trace, err := postExecutionPaused(pausedEventFor("after-give-up"), 500)
	require.NoError(t, err)
	assert.Equal(t, "RESUME_EXECUTION", command.Command)
	assert.False(t, trace.CachedAddr, "sans adresse gardée, la résolution se fait sur place")
	assert.Equal(t, int64(4), resolver.count(), "une résolution sur place, une seule")
	assert.True(t, schedulerAddr.get(hostport) != "", "l'adresse résolue sur place est gardée")
}

// Une tentative en arrière-plan est bornée par son propre délai : un
// résolveur qui ne répond pas n'occupe pas la résolution indéfiniment.
func TestSchedulerAddress_BackgroundResolutionAttemptIsBoundedByItsTimeout(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "2")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "60")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "1")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", "2")
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	resolver.set(30*time.Second, "127.0.0.1", nil) // ne répond pas avant le délai

	started := time.Now()
	warmSchedulerAddress()
	waitFor(t, 3*time.Second, "les deux tentatives ont expiré", func() bool {
		return resolver.count() >= 2 && !addrResolving()
	})
	elapsed := time.Since(started)

	assert.Equal(t, int64(2), resolver.count())
	assert.True(t, elapsed >= 120*time.Millisecond, "deux tentatives de 60 ms chacune : %s", elapsed)
	assert.True(t, elapsed < 2*time.Second, "bornées par SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS, pas par le résolveur : %s", elapsed)
	assert.Equal(t, "", schedulerAddr.get(hostport))
}

// L'attente entre deux tentatives double, puis plafonne : sans plafond, les
// dernières tentatives d'une résolution longtemps en échec s'espaceraient
// de plus en plus, et l'adresse resterait non gardée d'autant.
func TestSchedulerAddress_BackgroundResolutionBackoffDoublesThenIsCapped(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "8")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "10")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", "20")
	fs := newFakeSchedulerServer(t)
	_, resolver := useNamedScheduler(t, fs.server.URL)
	resolver.set(0, "", errors.New("no such host"))
	var mu sync.Mutex
	var calls []time.Time
	lookupHostFunc = func(ctx context.Context, host string) ([]string, error) {
		mu.Lock()
		calls = append(calls, time.Now())
		mu.Unlock()
		return resolver.lookup(ctx, host)
	}

	warmSchedulerAddress()
	waitFor(t, 5*time.Second, "résolution en arrière-plan abandonnée", func() bool {
		return resolver.count() >= 8 && !addrResolving()
	})

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, calls, 8)
	assert.True(t, calls[1].Sub(calls[0]) >= 10*time.Millisecond, "première attente = la base : %s", calls[1].Sub(calls[0]))
	for i := 2; i < len(calls); i++ {
		gap := calls[i].Sub(calls[i-1])
		assert.True(t, gap >= 20*time.Millisecond, "attente n° %d doublée (20 ms au moins) : %s", i, gap)
		assert.True(t, gap < 150*time.Millisecond, "attente n° %d plafonnée à 20 ms, pas 40, 80, 160… : %s", i, gap)
	}
}

// Ce que la grappe a montré le 2026-10-11 : une résolution sur sept reste
// bloquée 5 s pendant une montée de charge, alors qu'une seconde résolution,
// lancée entre-temps, aboutit en quelques millisecondes. Une requête perdue ne
// doit donc coûter qu'une tentative courte.

// Au démarrage : l'adresse est gardée après une tentative courte et une attente, pas après 5 s.
func TestSchedulerAddress_BackgroundResolution_ALostQueryCostsOneShortAttempt(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "100")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "10")
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	atomic.StoreInt64(&resolver.lostFirst, 1)

	started := time.Now()
	warmSchedulerAddress()
	waitFor(t, 3*time.Second, "adresse gardée malgré la requête perdue", func() bool { return schedulerAddr.get(hostport) != "" })
	elapsed := time.Since(started)

	assert.Equal(t, int64(2), resolver.count(), "une tentative perdue, une tentative aboutie")
	assert.True(t, elapsed >= 100*time.Millisecond, "la première tentative a attendu son délai : %s", elapsed)
	assert.True(t, elapsed < time.Second, "une tentative courte, pas le délai du résolveur : %s", elapsed)
	waitFor(t, time.Second, "résolution en arrière-plan terminée", func() bool { return !addrResolving() })
}

// Pendant un gel, sans adresse gardée : le signalement part après une tentative courte, dans son délai.
func TestSchedulerAddress_ColdCache_ALostQueryDoesNotCostThePauseEventItsDeadline(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "100")
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	atomic.StoreInt64(&resolver.lostFirst, 2) // deux requêtes perdues de suite

	started := time.Now()
	command, trace, err := postExecutionPaused(pausedEventFor("lost-query"), 2000)
	elapsed := time.Since(started)

	require.NoError(t, err)
	assert.Equal(t, "RESUME_EXECUTION", command.Command)
	assert.Equal(t, int64(3), resolver.count(), "deux tentatives perdues, la troisième aboutit")
	assert.True(t, elapsed >= 200*time.Millisecond && elapsed < time.Second, "deux tentatives de 100 ms, pas 5 s : %s", elapsed)
	assert.False(t, trace.CachedAddr)
	assert.Equal(t, "", trace.Failure)
	assert.True(t, trace.DNSNs >= (200*time.Millisecond).Nanoseconds(), "la durée de résolution enregistrée couvre les tentatives perdues : %d ns", trace.DNSNs)
	assert.True(t, schedulerAddr.get(hostport) != "", "l'adresse résolue sur place est gardée")
}

// Sans adresse gardée et sans réponse du tout : le nombre de tentatives sur place est borné.
func TestSchedulerAddress_ColdCache_InPlaceAttemptsAreBounded(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_TIMEOUT_MS", "20")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "4")
	fs := newFakeSchedulerServer(t)
	_, resolver := useNamedScheduler(t, fs.server.URL)
	atomic.StoreInt64(&resolver.lostFirst, 1000)

	_, trace, err := postExecutionPaused(pausedEventFor("never"), 2000)

	require.Error(t, err)
	assert.Equal(t, channelFailureResolve, trace.Failure)
	assert.Equal(t, int64(4), resolver.count(), "SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS tentatives, pas une de plus")
	assert.Empty(t, fs.getPausedEvents())
}

// Une réponse sans adresse n'est pas une adresse : c'est un échec de
// résolution, au démarrage comme sur place. Sans ce contrôle, le runtime se
// connecterait à « :port », c'est-à-dire à lui-même.
func TestSchedulerAddress_AnAnswerWithoutAddressIsAResolutionFailure(t *testing.T) {
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_MAX_ATTEMPTS", "2")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_BASE_MS", "1")
	t.Setenv("SCHEDULER_ADDRESS_RESOLVE_RETRY_BACKOFF_MAX_MS", "2")
	fs := newFakeSchedulerServer(t)
	hostport, resolver := useNamedScheduler(t, fs.server.URL)
	resolver.set(0, "", nil) // le résolveur répond, sans adresse

	warmSchedulerAddress()
	waitFor(t, 2*time.Second, "résolution en arrière-plan abandonnée", func() bool {
		return resolver.count() >= 2 && !addrResolving()
	})
	assert.Equal(t, "", schedulerAddr.get(hostport), "aucune adresse gardée")

	_, trace, err := postExecutionPaused(pausedEventFor("no-address"), 500)
	require.Error(t, err)
	assert.Equal(t, channelFailureResolve, trace.Failure)
	assert.Empty(t, fs.getPausedEvents(), "aucun signalement n'est parti vers une adresse vide")
	assert.Equal(t, "", schedulerAddr.get(hostport))
}
