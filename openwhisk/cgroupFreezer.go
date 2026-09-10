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

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cgroupFreezer.go implements CLAUDE.md §7.3 (cgroup freezer) and §7.4
// (runtime state machine): the idempotent freezeExecution/
// resumeExecution/killExecution primitives, and the RUNNING/FREEZING/
// FROZEN/RESUMING/KILLING/STOPPED/UNKNOWN states governing them.
//
// NOT wired into runHandler.go or Executor.Interact() in this phase —
// that round-trip (deciding WHEN to freeze, waiting for a scheduler
// command, resuming/killing on it) is phase 7's own design. This file
// delivers ActivationController as a self-contained, independently
// testable component: it owns a dedicated cgroup v2 group and the
// process placed into it, and the state machine around freeze/resume/
// kill of that whole group — never a signal to a single PID.
//
// Process placement uses CLONE_INTO_CGROUP (Go's SysProcAttr.CgroupFD,
// Linux 5.7+): the child is born directly inside the target cgroup at
// clone() time, so every thread and descendant it ever creates inherits
// membership automatically — there is no "spawn, then move" race window
// in which an early grandchild could be spawned before it's covered.
// This is what makes the freeze/kill genuinely cover "processus
// principal, threads, processus enfants, commandes lancées par l'action"
// as §7.3 requires, not just the main PID.

// RuntimeState is CLAUDE.md §7.4's internal runtime state.
type RuntimeState string

const (
	StateRunning  RuntimeState = "RUNNING"
	StateFreezing RuntimeState = "FREEZING"
	StateFrozen   RuntimeState = "FROZEN"
	StateResuming RuntimeState = "RESUMING"
	StateKilling  RuntimeState = "KILLING"
	StateStopped  RuntimeState = "STOPPED"
	StateUnknown  RuntimeState = "UNKNOWN"
)

// TransitionError is CLAUDE.md §7.4's "événement d'erreur structuré" for
// an unexpected/invalid state transition attempt. It is both a normal Go
// error (callers can just check err != nil) and a structured, inspectable
// event: tests and callers can type-assert it to read FromState/
// AttemptedOp/Reason directly, which does not depend on how (or whether)
// logging is configured — this package's own TestMain discards all
// log.Printf output by default (see util_test.go), so the log line
// emitted alongside this error is for operational visibility, not the
// sole carrier of the "structured event" guarantee.
type TransitionError struct {
	Event       string       `json:"event"`
	PauseID     string       `json:"pause_id"`
	AttemptedOp string       `json:"attempted_op"`
	FromState   RuntimeState `json:"from_state"`
	Reason      string       `json:"reason"`
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf(
		"invalid runtime state transition: op=%s from_state=%s pause_id=%s: %s",
		e.AttemptedOp, e.FromState, e.PauseID, e.Reason,
	)
}

func newTransitionError(op string, from RuntimeState, pauseID, reason string) *TransitionError {
	event := &TransitionError{
		Event:       "RUNTIME_STATE_TRANSITION_ERROR",
		PauseID:     pauseID,
		AttemptedOp: op,
		FromState:   from,
		Reason:      reason,
	}
	if encoded, err := json.Marshal(event); err == nil {
		log.Printf("[runtime_state] %s", encoded)
	} else {
		log.Printf("[runtime_state] %v (failed to marshal structured event: %v)", event, err)
	}
	return event
}

// --- cgroup v2 low-level handle -----------------------------------------

// cgroupHandle owns one dedicated cgroup v2 directory.
type cgroupHandle struct {
	path string // absolute path to this activation's own cgroup
}

// cgroupTimeout reads a *_TIMEOUT_MS env var (CLAUDE.md §8:
// CGROUP_FREEZE_TIMEOUT_MS, CGROUP_RESUME_TIMEOUT_MS,
// CGROUP_KILL_TIMEOUT_MS), following this repo's existing convention of
// reading env vars directly where used — no centralized config.go on the
// Go side.
func cgroupTimeout(envVar string, defaultMs int) time.Duration {
	ms := defaultMs
	if v := os.Getenv(envVar); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// cgroupMountRoot returns the cgroup v2 mount point, overridable via
// CGROUP_MOUNT_ROOT (tests use this to avoid depending on the real
// /sys/fs/cgroup layout... in practice we still exercise the real one,
// since a fake cgroupfs cannot be constructed outside the kernel).
func cgroupMountRoot() string {
	if v := os.Getenv("CGROUP_MOUNT_ROOT"); v != "" {
		return v
	}
	return "/sys/fs/cgroup"
}

// ownCgroupRelativePath reads this process's own cgroup v2 membership
// from /proc/self/cgroup (the single "0::/..." line in the unified
// hierarchy) so activation cgroups can be created as children of
// whatever subtree has already been delegated to this process (by
// systemd for a user/system session, or by the container runtime).
func ownCgroupRelativePath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/cgroup: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 (0::) entry in /proc/self/cgroup")
}

// cgroupBaseDir is the directory under which per-activation cgroups are
// created, overridable via CGROUP_BASE_DIR.
func cgroupBaseDir() (string, error) {
	if v := os.Getenv("CGROUP_BASE_DIR"); v != "" {
		return v, nil
	}
	own, err := ownCgroupRelativePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(cgroupMountRoot(), own, "ow-activations"), nil
}

// newCgroupHandle creates a fresh, empty cgroup v2 directory named
// `name` under cgroupBaseDir(). Fails if the delegation this process
// needs (an already-cgroup-v2-mounted, writable subtree) isn't
// available — callers should treat that as "cannot test/use real cgroup
// freezing in this environment" (CLAUDE.md's own instruction: report
// this clearly rather than simulate success).
func newCgroupHandle(name string) (*cgroupHandle, error) {
	base, err := cgroupBaseDir()
	if err != nil {
		return nil, fmt.Errorf("determine cgroup base dir: %w", err)
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return nil, fmt.Errorf("create cgroup base dir %s: %w", base, err)
	}
	path := filepath.Join(base, name)
	if err := os.Mkdir(path, 0755); err != nil {
		return nil, fmt.Errorf("create activation cgroup %s: %w", path, err)
	}
	return &cgroupHandle{path: path}, nil
}

// openDirFD opens the cgroup directory itself, for use as
// SysProcAttr.CgroupFD (CLONE_INTO_CGROUP).
func (c *cgroupHandle) openDirFD() (*os.File, error) {
	return os.Open(c.path)
}

// readEventField reads one "<field> <value>" line from cgroup.events.
func (c *cgroupHandle) readEventField(field string) (string, error) {
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.events"))
	if err != nil {
		return "", fmt.Errorf("read cgroup.events: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == field {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("field %q not found in cgroup.events", field)
}

// waitForEventField polls cgroup.events until `field` reads `want`, or
// times out. This is what makes freeze/resume "considered successful
// only after reading the cgroup's effective state" (§7.3): cgroup.freeze
// itself only reflects the requested setting, not whether the kernel has
// actually finished transitioning every task.
func (c *cgroupHandle) waitForEventField(field, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		got, err := c.readEventField(field)
		if err != nil {
			return err
		}
		if got == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for cgroup.events %s=%s (last read %s)", timeout, field, want, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *cgroupHandle) freeze() error {
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.freeze"), []byte("1"), 0644); err != nil {
		return fmt.Errorf("write cgroup.freeze=1: %w", err)
	}
	return c.waitForEventField("frozen", "1", cgroupTimeout("CGROUP_FREEZE_TIMEOUT_MS", 2000))
}

func (c *cgroupHandle) unfreeze() error {
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.freeze"), []byte("0"), 0644); err != nil {
		return fmt.Errorf("write cgroup.freeze=0: %w", err)
	}
	return c.waitForEventField("frozen", "0", cgroupTimeout("CGROUP_RESUME_TIMEOUT_MS", 2000))
}

// kill sends SIGKILL to every process in the cgroup at once
// (cgroup.kill, Linux 5.14+) — reaches descendants regardless of process
// group membership, including ones that called setsid() to escape it, a
// stronger guarantee than a process-group signal. Works correctly even
// if the cgroup is currently frozen (verified empirically: the kernel
// kills and reaps the tasks rather than leaving them stuck frozen).
func (c *cgroupHandle) kill() error {
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0644); err != nil {
		return fmt.Errorf("write cgroup.kill: %w", err)
	}
	return c.waitForEventField("populated", "0", cgroupTimeout("CGROUP_KILL_TIMEOUT_MS", 2000))
}

// remove deletes the (now-empty) cgroup directory.
func (c *cgroupHandle) remove() error {
	return os.Remove(c.path)
}

// --- ActivationController: state machine + primitives ---------------------

// waitOnce guards against calling exec.Cmd.Wait() more than once — Go's
// os/exec explicitly forbids that (a second call returns an error
// instead of the real exit status, and the behaviour around concurrent
// calls is undefined). Both Executor's own background reaper goroutine
// (executor.go's Start(), via WaitForExit below) and killExecution()'s
// own "confirm genuinely reaped, not just cgroup-unpopulated" wait share
// one of these: whichever call happens first does the real cmd.Wait(),
// every other caller just observes the same cached result.
type waitOnce struct {
	once sync.Once
	err  error
}

func (w *waitOnce) wait(cmd *exec.Cmd) error {
	w.once.Do(func() {
		w.err = cmd.Wait()
	})
	return w.err
}

// ActivationController owns one activation's dedicated cgroup and the
// CLAUDE.md §7.4 state machine governing it.
type ActivationController struct {
	mu     sync.Mutex
	cg     *cgroupHandle
	cmd    *exec.Cmd
	state  RuntimeState
	waiter *waitOnce

	// Idempotency key memory (§7.7's requirement generalised to these
	// lower-level primitives): the last pause_id a freeze/resume/kill
	// call was confirmed under.
	lastPauseID string
}

// NewActivationController creates the dedicated cgroup for one
// activation (CLAUDE.md §7.3). `name` must be a unique, filesystem-safe
// identifier (the caller's choice — e.g. derived from trace_id).
func NewActivationController(name string) (*ActivationController, error) {
	cg, err := newCgroupHandle(name)
	if err != nil {
		return nil, err
	}
	return &ActivationController{cg: cg, state: StateRunning, waiter: &waitOnce{}}, nil
}

// Start places cmd directly into the activation's cgroup at process
// creation time (CLONE_INTO_CGROUP) and starts it. The caller configures
// cmd's Path/Args/Stdin/Stdout/Stderr/Env as usual; Start only sets
// SysProcAttr and calls cmd.Start().
func (a *ActivationController) Start(cmd *exec.Cmd) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	fd, err := a.cg.openDirFD()
	if err != nil {
		return fmt.Errorf("open cgroup dir for CLONE_INTO_CGROUP: %w", err)
	}
	defer fd.Close()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(fd.Fd()),
		// Also a process group leader, consistent with phase 5's
		// killProcessGroup() fallback — harmless alongside cgroup
		// membership, not relied on here (cgroup.kill is what this
		// controller actually uses).
		Setpgid: true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start process into cgroup: %w", err)
	}
	a.cmd = cmd
	a.state = StateRunning
	return nil
}

// State returns the controller's current runtime state.
func (a *ActivationController) State() RuntimeState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

// Pid returns the tracked process's PID, or 0 if none has been started.
func (a *ActivationController) Pid() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cmd == nil || a.cmd.Process == nil {
		return 0
	}
	return a.cmd.Process.Pid
}

// CgroupPath returns the absolute path to this activation's own dedicated
// cgroup v2 directory — the one CLONE_INTO_CGROUP placed the tracked
// process into at Start() time. Diagnostic-only accessor (added to
// compare this against what readProcessTicks() independently resolves
// for the same PID, per CLAUDE.md §7.3's own mechanism — see
// cmd/verify_cgroup_pod).
func (a *ActivationController) CgroupPath() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cg.path
}

// Close removes the activation's cgroup directory. Only valid once the
// cgroup is empty (state STOPPED, or never started).
func (a *ActivationController) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cg.remove()
}

// freezeExecution: RUNNING -> FREEZING -> FROZEN (CLAUDE.md §7.3, §7.4).
// Idempotent: a repeat call with the SAME pauseID while already FROZEN
// under it is a no-op, not a re-freeze attempt or an error.
func (a *ActivationController) freezeExecution(traceID, reservationID, pauseID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == StateFrozen && a.lastPauseID == pauseID {
		return nil // idempotent repeat, CLAUDE.md §7.3/§7.7
	}
	if a.state != StateRunning {
		return newTransitionError(
			"freeze", a.state, pauseID,
			"freezeExecution requires RUNNING (or an idempotent repeat of the current FROZEN pause_id)",
		)
	}

	a.state = StateFreezing
	if err := a.cg.freeze(); err != nil {
		a.state = StateUnknown
		return newTransitionError("freeze", StateFreezing, pauseID, err.Error())
	}
	a.state = StateFrozen
	a.lastPauseID = pauseID
	return nil
}

// resumeExecution: FROZEN -> RESUMING -> RUNNING (CLAUDE.md §7.3, §7.4).
// Idempotent: a repeat call with the SAME pauseID while already RUNNING
// from that resume is a no-op.
func (a *ActivationController) resumeExecution(traceID, reservationID, pauseID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == StateRunning && a.lastPauseID == pauseID {
		return nil // idempotent repeat
	}
	if a.state != StateFrozen {
		return newTransitionError(
			"resume", a.state, pauseID,
			"resumeExecution requires FROZEN (or an idempotent repeat of the pause_id just resumed)",
		)
	}
	if pauseID != a.lastPauseID {
		return newTransitionError(
			"resume", a.state, pauseID,
			fmt.Sprintf("pause_id mismatch: currently frozen under %q", a.lastPauseID),
		)
	}

	a.state = StateResuming
	if err := a.cg.unfreeze(); err != nil {
		a.state = StateUnknown
		return newTransitionError("resume", StateResuming, pauseID, err.Error())
	}
	a.state = StateRunning
	a.lastPauseID = pauseID
	return nil
}

// killExecution: RUNNING -> KILLING -> STOPPED, or FROZEN -> KILLING ->
// STOPPED (CLAUDE.md §7.3, §7.4 — the pauseEnabled=false forward-phase
// kill already in place since phase 5, energyMonitor.go's
// killProcessGroup(), is the SAME RUNNING -> KILLING -> STOPPED
// transition conceptually; it is not re-routed through this controller
// in this phase — that integration is phase 7 — but this state machine
// does not need a second, separate path to represent it). Idempotent:
// already-STOPPED is a no-op.
func (a *ActivationController) killExecution(traceID, reservationID, pauseID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == StateStopped {
		return nil // idempotent repeat
	}
	if a.state != StateRunning && a.state != StateFrozen {
		return newTransitionError(
			"kill", a.state, pauseID,
			"killExecution requires RUNNING or FROZEN",
		)
	}

	a.state = StateKilling

	// INSTRUMENTATION (2026-09-10). Ce chemin a ete localise par mesure
	// comme celui ou le runtime disparait sous saturation : le conteneur
	// journalise « KILL_EXECUTION received » puis PLUS RIEN — ni echec de
	// killExecution, ni EXECUTION_KILLED — jusqu'a ce que l'invoker
	// reclame le conteneur a 180 s (LIMITE_KILL_NON_CONFIRME.md, trace
	// 34012ac8). Deux attentes seulement peuvent l'expliquer, et les
	// lignes ci-dessous les separent sans ambiguite :
	//   - cg.kill() -> bornee par CGROUP_KILL_TIMEOUT_MS, et un
	//     depassement RETOURNE une erreur (donc serait deja journalise) ;
	//   - waiter.wait() -> NON bornee, et c'est un sync.Once partage avec
	//     le ramasseur d'arriere-plan de Executor.Start(). sync.Once.Do
	//     bloque les appelants concurrents jusqu'au retour du PREMIER :
	//     si le ramasseur est deja dans cmd.Wait() sur un processus qui
	//     ne meurt pas, on y reste indefiniment.
	// Noter que le verrou a.mu est tenu pendant toute la fonction : un
	// blocage ici gele aussi toute autre operation du controleur.
	killStart := time.Now()
	if err := a.cg.kill(); err != nil {
		a.state = StateUnknown
		log.Printf(
			"[kill] trace=%s pause=%s: cgroup.kill ECHEC apres %.1f ms: %v",
			traceID, pauseID, float64(time.Since(killStart).Microseconds())/1000.0, err,
		)
		return newTransitionError("kill", StateKilling, pauseID, err.Error())
	}
	log.Printf(
		"[kill] trace=%s pause=%s: cgroup.kill confirme (populated=0) en %.1f ms — "+
			"attente de reaping ensuite",
		traceID, pauseID, float64(time.Since(killStart).Microseconds())/1000.0,
	)

	// cgroup.events populated=0 confirms the kernel has torn the process
	// down, but it may still be a zombie until reaped — STOPPED must
	// mean genuinely gone, not just cgroup-unpopulated (a caller probing
	// liveness via kill(pid, 0) would otherwise still see it "alive").
	if a.cmd != nil {
		waitStart := time.Now()
		if budget := killConfirmWaitTimeout(); budget > 0 {
			// Borne OPTIONNELLE, desactivee par defaut (voir
			// killConfirmWaitTimeout) : le comportement livre reste
			// exactement celui d'avant tant que la variable n'est pas
			// posee. Elle existe pour pouvoir VALIDER le correctif
			// pressenti sans un second cycle de reconstruction d'image.
			done := make(chan struct{})
			go func() {
				_ = a.waiter.wait(a.cmd)
				close(done)
			}()
			select {
			case <-done:
				log.Printf(
					"[kill] trace=%s pause=%s: processus reape en %.1f ms",
					traceID, pauseID, float64(time.Since(waitStart).Microseconds())/1000.0,
				)
			case <-time.After(budget):
				logSafetyKillConfirmTimeout(traceID, reservationID, pauseID, budget)
			}
		} else {
			_ = a.waiter.wait(a.cmd)
			log.Printf(
				"[kill] trace=%s pause=%s: processus reape en %.1f ms",
				traceID, pauseID, float64(time.Since(waitStart).Microseconds())/1000.0,
			)
		}
	}
	a.state = StateStopped
	a.lastPauseID = pauseID
	return nil
}

// killConfirmWaitTimeout lit KILL_CONFIRM_WAIT_TIMEOUT_MS. Defaut 0 =
// AUCUNE borne, c'est-a-dire le comportement historique inchange : cette
// fonction est livree pour instrumenter, pas pour modifier la conduite
// sans decision explicite.
//
// Poser une valeur > 0 borne l'attente de reaping qui SUIT la confirmation
// `populated=0`. C'est defendable : a ce stade le noyau a deja demantele le
// processus, l'attente ne couvre plus que la moisson du zombie. La
// depasser signifie qu'on n'a pas pu confirmer la moisson, pas que le
// processus survit — d'ou un incident [safety] plutot qu'un echec.
func killConfirmWaitTimeout() time.Duration {
	ms := 0
	if v := os.Getenv("KILL_CONFIRM_WAIT_TIMEOUT_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// logSafetyKillConfirmTimeout signale que la moisson du processus n'a pas
// pu etre confirmee dans le budget imparti. Le cgroup est vide
// (`populated=0` verifie juste avant), donc la garantie energetique tient ;
// ce qui manque est la confirmation de moisson.
func logSafetyKillConfirmTimeout(traceID, reservationID, pauseID string, budget time.Duration) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":          "KILL_CONFIRM_WAIT_TIMEOUT",
		"severity":       "warning",
		"trace_id":       traceID,
		"reservation_id": reservationID,
		"pause_id":       pauseID,
		"budget_ms":      budget.Milliseconds(),
		"detail": "cgroup.kill confirmed populated=0, but reaping the process " +
			"could not be confirmed within the budget. The cgroup is empty, so " +
			"the energy guarantee holds; the kill is reported as confirmed and " +
			"EXECUTION_KILLED is emitted rather than leaving the runtime blocked.",
	})
	if err != nil {
		log.Printf("[safety] KILL_CONFIRM_WAIT_TIMEOUT trace=%s (marshal failed: %v)", traceID, err)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// WaitForExit blocks until the tracked process has exited, returning
// exec.Cmd.Wait()'s error (nil for a normal, zero exit). Safe to call
// concurrently with, or after, killExecution()'s own internal
// confirmation wait — see waitOnce above; only one of them ever actually
// calls cmd.Wait().
func (a *ActivationController) WaitForExit() error {
	a.mu.Lock()
	cmd := a.cmd
	waiter := a.waiter
	a.mu.Unlock()
	if cmd == nil {
		return fmt.Errorf("WaitForExit: no process started")
	}
	return waiter.wait(cmd)
}
