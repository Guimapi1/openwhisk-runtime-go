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
	"strconv"
	"strings"
	"sync"
	"time"
)

// energyMonitor.go implements CLAUDE.md §3.1 / §7.2's threshold
// detection, and — as of PLAYBOOK.md Phase 7 — the full forward-phase
// pause/extension/resume round-trip for the pauseEnabled=true case
// (§5's runtime steps 4-7, §7.5): freeze, EXECUTION_PAUSED over the
// dedicated scheduler channel (schedulerChannel.go), wait for the
// scheduler's RESUME_EXECUTION/KILL_EXECUTION command, then resume with
// an updated threshold or kill.
//
// pauseEnabled=false keeps CLAUDE.md §3.1's original behaviour: an
// immediate, local, synchronous kill with no round-trip — but the kill
// primitive itself is now controller.killExecution() (cgroup.kill),
// never a bare process-group signal (PLAYBOOK.md Phase 7's resolved
// open question #3: killExecution is the SOLE kill path from this phase
// on, covering descendants that escaped the process group via setsid(),
// which a process-group signal cannot reach).
//
// The runtime never decides between resuming and killing on its own
// initiative once a scheduler command IS received (CLAUDE.md §7.1) —
// only when the scheduler cannot be reached or answers with something
// undecodable does this file fall back to killing locally, treated the
// same as any other "cannot safely continue" case (see runPauseCycle).

// EnergyKillInfo is returned by Executor.Interact() when the energy
// monitor killed the process: nil for a normal completion, or a failure
// unrelated to the energy threshold.
type EnergyKillInfo struct {
	// EnergyConsumedJ is the energy measured for THIS step only, up to
	// the moment of the kill (not including consumed_before_j — the
	// caller, runHandler.go, adds that to build the cumulative total for
	// the EXECUTION_KILLED event, CLAUDE.md §7.6).
	EnergyConsumedJ float64
	// PauseID is the active pause cycle's ID if this kill followed a
	// freeze/EXECUTION_PAUSED cycle (CLAUDE.md §7.6's EXECUTION_KILLED
	// event carries it in that case), or "" if the process was killed
	// directly, without ever pausing (pauseEnabled=false, §3.1).
	PauseID string
}

// energyMonitorInterval reads ENERGY_MONITOR_INTERVAL_MS (CLAUDE.md §8,
// default 100ms). Read directly via os.Getenv, following this repo's
// existing convention (e.g. RAPL_PATH in metrics_helpers.go) — there is
// no centralized config.go on the Go side.
func energyMonitorInterval() time.Duration {
	ms := 100
	if v := os.Getenv("ENERGY_MONITOR_INTERVAL_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// energyMonitorResult is written once by the monitor goroutine and read
// by Interact() only after the monitor has fully stopped (see
// Interact()'s use of monitorFinished) — the mutex guards against the
// (harmless but still real) memory-visibility hazard of writing in one
// goroutine and reading in another without synchronization, even though
// the happens-before relationship is already established by the
// channel close/receive.
type energyMonitorResult struct {
	mu        sync.Mutex
	killed    bool
	consumedJ float64
	pauseID   string
}

func (r *energyMonitorResult) setKilled(consumedJ float64, pauseID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.killed = true
	r.consumedJ = consumedJ
	r.pauseID = pauseID
}

func (r *energyMonitorResult) get() (bool, float64, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.killed, r.consumedJ, r.pauseID
}

// shortActionName mirrors scheduler/core/registry.py::_short_name()
// EXACTLY (CLAUDE.md §6.3: "cette normalisation doit être appliquée de
// façon identique partout où un nom d'action est comparé... pas
// réinventée séparément à chaque phase") — text after the last "/", the
// whole qualified string unchanged if no "/" is present, "" if the
// input is "" or ends in "/". Deliberately NOT path.Base/filepath.Base:
// both diverge from _short_name on "" (returns "." not ""), a trailing
// "/" (returns the preceding segment, not ""), and "/" alone (returns
// "/" not "").
func shortActionName(qualified string) string {
	return qualified[strings.LastIndex(qualified, "/")+1:]
}

// isNonInterruptibleForThisStep resolves THIS step's own interruption
// class (PLAYBOOK.md Phase 10) from the per-component map carried in
// EnergyState.InterruptionClass (energy_state.go), keyed by
// energy.ResolvedActionName — reliably decoded by runHandler.go from
// OpenWhisk's own per-activation /run payload (docs/ACTION.md's
// "action_name" field, always present) and short-normalized the same
// way the scheduler's own map keys are (shortActionName() above).
//
// Previously keyed by __OW_ACTION_NAME (os.Getenv), which is NEVER SET
// in this proxy's own process — only in the CHILD action's environment,
// derived by the language layer FROM this same JSON payload — so the
// lookup always missed in production despite passing every test (every
// test injected the env var directly via t.Setenv, a blind spot the
// real fix (runHandler.go decoding action_name) closes). A real
// incident: this made a NON_INTERRUPTIBLE action's own freeze/kill
// enforcement fire exactly as if no interruption_class had ever been
// declared for it.
//
// Defense in depth (CLAUDE.md §3.3, hardening fix): if the resolved
// name is still EMPTY — this step's own action_name could not be
// decoded at all, a genuine resolution failure — the default is to NOT
// enforce, the reverse of the previous "safe default is enforced"
// assumption, which had it backwards. A trace that runs unmonitored
// already has a safe, tested catch-all (committed_j credited uncapped
// at settlement, a dedicated [safety] log — CLAUDE.md §3.3). A
// NON_INTERRUPTIBLE action frozen or killed by mistake has no recovery
// path at all. Between under-enforcing a genuinely interruptible action
// and destroying a genuinely NON_INTERRUPTIBLE one, the former is the
// strictly safer failure mode. Should now be rare after the
// action_name fix above — every occurrence is logged as a critical
// [safety] incident (logUnresolvedInterruptionClass), not silently
// absorbed, since it signals the resolution mechanism itself failed,
// not an expected/accounted-for outcome.
//
// A resolved (non-empty) name simply ABSENT from the map is NOT the
// same failure — real incident, PLAYBOOK.md Phase 9's recovery-side
// pause/extend/resume demonstration: this is the NORMAL, EXPECTED shape
// for a compensation action (CLAUDE.md §6.3, "interruption_class n'est
// pas exigée sur une action déclarée uniquement comme cible de
// compensation_sequence" — core/scheduler.py::_interruption_class_map()
// deliberately OMITS such an action from the map it sends). Treating
// this identically to a genuine resolution failure silently disabled
// shouldMonitorEnergy() (below) for EVERY compensation with a
// pause_policy — the entire §3.2 "phase recovery — pause et extension
// désormais applicables" mechanism was inert in production: a
// compensation could overshoot its threshold by tens of joules with
// ample real time to spare and never freeze, confirmed live. The two
// cases are distinguished by ResolvedActionName itself, not by map
// membership: empty means decoding failed (real error, fail safe);
// non-empty-but-absent means this specific action legitimately carries
// no interruption_class (§6.3's own compensation-action exception,
// enforce normally — its pause_policy, an independent field per §2, is
// what actually governs freezing here).
func isNonInterruptibleForThisStep(energy *EnergyState) bool {
	if energy == nil || energy.InterruptionClass == nil {
		return false
	}
	if energy.ResolvedActionName == "" {
		// Genuine resolution failure — "the strictly safer failure mode
		// is to NOT kill" (header note). The [safety] log for this case
		// is emitted ONCE, by shouldMonitorEnergy()'s path, not here
		// (this function is now also called repeatedly from
		// runPauseCycle()'s re-poll loop, where logging would spam).
		return true
	}
	class, ok := energy.InterruptionClass[energy.ResolvedActionName]
	if !ok {
		// Expected shape for a compensation action (see above) — not a
		// resolution failure, no critical log, enforce normally.
		return false
	}
	// PLAYBOOK.md Phase 16 (CLAUDE.md §0 decision 18): renamed value.
	// This step must be FROZEN and EXTENDED like any other class
	// (shouldMonitorEnergy() no longer skips it) but NEVER killed —
	// runPauseCycle() refuses every kill path for it.
	return class == "UNKILLABLE"
}

// interruptionClassUnresolved: this step carried a per-component
// interruption-class map but its OWN action name could not be decoded at
// all — a genuine failure of the resolution mechanism (distinct from a
// resolved name legitimately absent from the map, the compensation-
// action case). Fail-safe: shouldMonitorEnergy() then skips enforcement
// entirely rather than risk killing (pauseEnabled=false) or even
// freezing an action whose class is unknown.
func interruptionClassUnresolved(energy *EnergyState) bool {
	return energy != nil && energy.InterruptionClass != nil && energy.ResolvedActionName == ""
}

// unkillableRepollInterval reads UNKILLABLE_REPOLL_INTERVAL_MS (default
// 1000ms): how long an UNKILLABLE step stays frozen between re-POSTing
// EXECUTION_PAUSED while it waits in the scheduler's priority energy
// queue for capacity (CLAUDE.md §4.11, PLAYBOOK.md Phase 16). Env read
// directly, per this repo's convention.
func unkillableRepollInterval() time.Duration {
	ms := 1000
	if v := os.Getenv("UNKILLABLE_REPOLL_INTERVAL_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// logSafetyUnkillable emits a structured [safety] incident for an
// UNKILLABLE step that hit a path which, for any other class, would have
// ended in a local kill — the kill is refused instead (§3.3, §0 decision
// 18). `severity` is "critical" for a scheduler command that should
// never have been sent (KILL_EXECUTION) or a broken invariant
// (freeze/resume failure), "warning" for a transient channel issue the
// re-poll loop simply retries through.
func logSafetyUnkillable(event, severity string, energy *EnergyState, pauseID, detail string) {
	traceID, reservationID, resolved := "", "", ""
	if energy != nil {
		traceID, reservationID, resolved = energy.TraceID, energy.ReservationID, energy.ResolvedActionName
	}
	encoded, err := json.Marshal(map[string]interface{}{
		"event":                event,
		"severity":             severity,
		"trace_id":             traceID,
		"reservation_id":       reservationID,
		"pause_id":             pauseID,
		"resolved_action_name": resolved,
		"detail":               detail,
	})
	if err != nil {
		log.Printf("[safety] %s for trace=%s (marshal failed: %v): %s", event, traceID, err, detail)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// logUnresolvedInterruptionClass emits a critical-severity [safety] log
// whenever this step's own interruption class could not be resolved —
// distinct from NON_INTERRUPTIBLE_OVERAGE (core/reservation.py's
// existing log, which signals an EXPECTED, accounted-for overage): this
// one signals a failure of the resolution mechanism itself. Mirrors
// energy_state.go::logCorruptedEnergyState()'s own structured-JSON
// pattern.
func logUnresolvedInterruptionClass(energy *EnergyState) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":                  "INTERRUPTION_CLASS_UNRESOLVED",
		"severity":               "critical",
		"trace_id":               energy.TraceID,
		"reservation_id":         energy.ReservationID,
		"resolved_action_name":   energy.ResolvedActionName,
		"interruption_class_map": energy.InterruptionClass,
		"detail": "this step's own interruption class could not be resolved from " +
			"InterruptionClass — defaulting to NOT enforcing (fail-safe) rather than " +
			"risk freezing/killing an UNKILLABLE action by mistake",
	})
	if err != nil {
		log.Printf(
			"[safety] interruption class unresolved for trace=%s (failed to marshal structured event: %v)",
			energy.TraceID, err,
		)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// shouldMonitorEnergy mirrors CLAUDE.md §7.2: a disabled/negative
// threshold or no energy state at all (§7.5's third case) means no
// threshold ENFORCEMENT loop. Measurement itself is unaffected either
// way — runHandler.go's start/end readEnergy snapshots run
// unconditionally.
//
// PLAYBOOK.md Phase 16 (CLAUDE.md §0 decision 18, §3.3): an UNKILLABLE
// step is NO LONGER excluded here — it is monitored, frozen and extended
// like any other class; only the KILL paths in runPauseCycle() are
// refused for it. The ONE remaining reason to skip enforcement on a
// class basis is an UNRESOLVED interruption class (the step's own action
// name couldn't be decoded): a genuine resolution failure, fail-safe to
// NOT enforce (could be a real UNKILLABLE we'd wrongly freeze/kill).
// That case is logged once, here.
func shouldMonitorEnergy(energy *EnergyState) bool {
	if energy == nil || energy.ExecutionThresholdJ <= 0 {
		return false
	}
	if interruptionClassUnresolved(energy) {
		logUnresolvedInterruptionClass(energy)
		return false
	}
	return true
}

// monitorEnergy periodically measures the energy attributed to proc's
// PID since this step started. When consumed_before_j + measured reaches
// the (possibly since-updated, see runPauseCycle) threshold:
//   - PauseEnabled=false: kill immediately, locally, synchronously — no
//     notification to the scheduler beforehand (CLAUDE.md §3.1).
//   - PauseEnabled=true: run one freeze/EXECUTION_PAUSED/resume-or-kill
//     cycle (runPauseCycle). On a successful resume, monitoring continues
//     with the updated threshold — a trace can go through more than one
//     pause cycle in principle (the runtime does not know or care about
//     max_pause_count; that ceiling is enforced scheduler-side, §4.7,
//     via an immediate KILL_EXECUTION once it's reached).
//
// Always closes `finished` on return (even via the `stop` early-exit
// path), which Interact() waits on before reading `result` — this is
// what makes reading energyMonitorResult race-free.
func (proc *Executor) monitorEnergy(
	initialEnergy *EnergyState,
	stop <-chan struct{},
	finished chan<- struct{},
	result *energyMonitorResult,
) {
	defer close(finished)

	// A local, mutable copy: ExecutionThresholdJ evolves across pause
	// cycles (runPauseCycle updates it on a successful resume) without
	// touching the caller's own EnergyState.
	energy := *initialEnergy
	actionName := energy.ResolvedActionName

	energyStart, err := readEnergy()
	if err != nil {
		log.Printf("[energy_monitor] readEnergy start (trace=%s): %v", energy.TraceID, err)
		return
	}
	cpuStart := readCPUSnapshot(proc.Pid())

	ticker := time.NewTicker(energyMonitorInterval())
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			energyNow, err := readEnergy()
			if err != nil {
				log.Printf("[energy_monitor] readEnergy (trace=%s): %v", energy.TraceID, err)
				continue
			}
			cpuNow := readCPUSnapshot(proc.Pid())
			stepJ := float64(attributedEnergyUJ(energyStart, energyNow, cpuStart, cpuNow)) / 1e6

			if energy.ConsumedBeforeJ+stepJ < energy.ExecutionThresholdJ {
				continue
			}

			if !energy.PauseEnabled {
				if isNonInterruptibleForThisStep(&energy) {
					// PLAYBOOK.md Phase 16 (CLAUDE.md §3.3, §3.4): an
					// UNKILLABLE action ALWAYS has a mandatory pause_policy
					// (registry-enforced), so pauseEnabled=false here can
					// only mean this step's class is UNRESOLVED and the
					// fail-safe treats it as UNKILLABLE. Refuse the local
					// kill; let it run unmonitored (the scheduler's own
					// settlement catch-all, §3.3, still accounts for it).
					logSafetyUnkillable(
						"LOCAL_KILL_REFUSED_UNKILLABLE", "critical", &energy, "",
						"threshold reached with pauseEnabled=false for a step "+
							"resolved locally as UNKILLABLE (or unresolvable) — "+
							"local kill REFUSED, action NOT killed, monitoring stops",
					)
					return
				}
				log.Printf(
					"[energy_monitor] threshold reached for trace=%s: consumed_before=%.4fJ + "+
						"step=%.4fJ >= threshold=%.4fJ — killing locally, synchronously "+
						"(pauseEnabled=false, CLAUDE.md §3.1).",
					energy.TraceID, energy.ConsumedBeforeJ, stepJ, energy.ExecutionThresholdJ,
				)
				if err := proc.controller.killExecution(energy.TraceID, energy.ReservationID, ""); err != nil {
					log.Printf("[energy_monitor] killExecution failed for trace=%s: %v", energy.TraceID, err)
				}
				result.setKilled(stepJ, "")
				return
			}

			newThresholdJ, killed, pauseID := proc.runPauseCycle(&energy, actionName, stepJ)
			if killed {
				result.setKilled(stepJ, pauseID)
				return
			}
			energy.ExecutionThresholdJ = newThresholdJ
		}
	}
}

// runPauseCycle executes ONE freeze -> EXECUTION_PAUSED -> wait for the
// scheduler's command -> resume-or-kill cycle (CLAUDE.md §5, §7.5 steps
// 4-7). Returns (newThresholdJ, killed=false, pauseID) on a successful
// resume, or (_, killed=true, pauseID) once the process has been killed —
// either directly on the scheduler's own KILL_EXECUTION, or because this
// runtime could not safely continue (freeze failure, unreachable
// scheduler, undecodable/mismatched command): in every "cannot safely
// continue" case, killing is the only way to bound energy consumption
// without an explicit resume authorization (CLAUDE.md §4.3's invariant:
// resume_allowed(pause_id) => extension_success(pause_id) — this runtime
// has no way to satisfy that without a genuine RESUME_EXECUTION for THIS
// pause_id).
func (proc *Executor) runPauseCycle(
	energy *EnergyState, actionName string, stepJ float64,
) (newThresholdJ float64, killed bool, pauseID string) {
	pauseID = newPauseID()
	// PLAYBOOK.md Phase 16 (CLAUDE.md §0 decision 18, §3.3): resolved
	// ONCE per cycle. For an UNKILLABLE step, EVERY path that would
	// otherwise end in a local kill (freeze failure, channel failure,
	// stale/mismatched command, resume failure, an explicit
	// KILL_EXECUTION command, an unknown command) instead logs a
	// [safety] incident, keeps the process frozen, and re-POSTs
	// EXECUTION_PAUSED after a backoff — the trace can only ever leave
	// this cycle via a genuine RESUME_EXECUTION.
	unkillable := isNonInterruptibleForThisStep(energy)
	requestedAt := time.Now()

	if err := proc.controller.freezeExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
		if unkillable {
			logSafetyUnkillable(
				"FREEZE_FAILED_UNKILLABLE", "critical", energy, pauseID,
				fmt.Sprintf("freezeExecution failed (%v) — cannot kill an UNKILLABLE "+
					"step (§3.3); continuing best-effort with the current threshold, "+
					"this trace's budget may be exceeded", err),
			)
			return energy.ExecutionThresholdJ, false, pauseID
		}
		log.Printf(
			"[safety] freezeExecution failed for trace=%s pause=%s: %v — killing "+
				"(cannot safely continue monitoring an unfrozen, over-threshold process).",
			energy.TraceID, pauseID, err,
		)
		if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
		}
		return 0, true, pauseID
	}
	effectiveAt := time.Now()
	freezeLatencyMs := float64(effectiveAt.Sub(requestedAt).Microseconds()) / 1000.0

	event := ExecutionPausedEvent{
		Event:            "EXECUTION_PAUSED",
		TraceID:          energy.TraceID,
		ReservationID:    energy.ReservationID,
		PauseID:          pauseID,
		ActionName:       actionName,
		ExecutionPhase:   energy.ExecutionPhase,
		EnergyConsumedJ:  energy.ConsumedBeforeJ + stepJ,
		PauseRequestedAt: float64(requestedAt.UnixNano()) / 1e9,
		PauseEffectiveAt: float64(effectiveAt.UnixNano()) / 1e9,
		FreezeLatencyMs:  freezeLatencyMs,
	}
	log.Printf(
		"[pause] EXECUTION_PAUSED trace=%s pause=%s energy_consumed_j=%.4f freeze_latency_ms=%.2f",
		energy.TraceID, pauseID, event.EnergyConsumedJ, freezeLatencyMs,
	)

	// killOrRetry is the single choke point for every "cannot safely
	// continue" branch below: kill for any normal class, re-poll (never
	// kill) for UNKILLABLE. Returns true when the caller should `return`
	// a kill, false when it should re-loop.
	killOrRetry := func(event, severity, detail string) (float64, bool, string, bool) {
		if unkillable {
			logSafetyUnkillable(event, severity, energy, pauseID, detail+
				" — UNKILLABLE step, NOT killed; staying frozen, re-polling")
			time.Sleep(unkillableRepollInterval())
			return 0, false, pauseID, true // retry
		}
		log.Printf("[safety] %s for trace=%s pause=%s — killing (%s).", event, energy.TraceID, pauseID, detail)
		if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
		}
		return 0, true, pauseID, false // kill, do not retry
	}

	for {
		command, err := postExecutionPaused(event, energy.MaxPauseDurationMs)
		if err != nil {
			if nt, k, pid, retry := killOrRetry("PAUSE_CHANNEL_FAILED", "warning",
				fmt.Sprintf("EXECUTION_PAUSED channel call failed: %v", err)); !retry {
				return nt, k, pid
			}
			continue
		}

		if command.PauseID != pauseID {
			// CLAUDE.md §6.6: a stale/mismatched pause_id is ignored and
			// logged. For a normal class there is no cycle left to
			// resume into -> kill; for UNKILLABLE -> re-poll.
			if nt, k, pid, retry := killOrRetry("PAUSE_ID_MISMATCH", "warning",
				fmt.Sprintf("scheduler command pause_id=%q does not match active pause=%q", command.PauseID, pauseID)); !retry {
				return nt, k, pid
			}
			continue
		}

		switch command.Command {
		case "RESUME_EXECUTION":
			if err := proc.controller.resumeExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
				if nt, k, pid, retry := killOrRetry("RESUME_FAILED", "critical",
					fmt.Sprintf("resumeExecution failed: %v", err)); !retry {
					return nt, k, pid
				}
				continue
			}
			log.Printf(
				"[resume] trace=%s pause=%s resumed, new_threshold=%.4fJ",
				energy.TraceID, pauseID, command.NewExecutionThresholdJ,
			)
			return command.NewExecutionThresholdJ, false, pauseID

		case "WAIT_EXECUTION":
			// PLAYBOOK.md Phase 16 (CLAUDE.md §4.11): the scheduler has
			// queued this UNKILLABLE step's extension request in the
			// priority energy wait queue. Stay frozen, re-ask.
			if !unkillable {
				if nt, k, pid, retry := killOrRetry("UNEXPECTED_WAIT_COMMAND", "critical",
					"WAIT_EXECUTION is only valid for an UNKILLABLE step"); !retry {
					return nt, k, pid
				}
				continue
			}
			log.Printf(
				"[pause] WAIT_EXECUTION trace=%s pause=%s reason=%s — UNKILLABLE awaiting "+
					"capacity (§4.11), staying frozen, re-polling in %s.",
				energy.TraceID, pauseID, command.Reason, unkillableRepollInterval(),
			)
			time.Sleep(unkillableRepollInterval())
			continue

		case "KILL_EXECUTION":
			if unkillable {
				// Defense in depth (PLAYBOOK.md Phase 16 objective 3):
				// the scheduler must NEVER send this for an UNKILLABLE
				// step, but if one arrives, do not trust it blindly —
				// refuse, log a critical [safety] incident, keep frozen
				// and re-poll. Mirrors this repo's own caution around
				// action-name resolution.
				logSafetyUnkillable(
					"KILL_EXECUTION_REFUSED_UNKILLABLE", "critical", energy, pauseID,
					fmt.Sprintf("scheduler sent KILL_EXECUTION (reason=%q) for a step "+
						"resolved locally as UNKILLABLE — command IGNORED, action NOT "+
						"killed (§3.3, §0 decision 18); staying frozen, re-polling", command.Reason),
				)
				time.Sleep(unkillableRepollInterval())
				continue
			}
			log.Printf("[energy_monitor] KILL_EXECUTION received for trace=%s pause=%s reason=%s", energy.TraceID, pauseID, command.Reason)
			if err := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
				log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, err)
			}
			return 0, true, pauseID

		default:
			if nt, k, pid, retry := killOrRetry("UNKNOWN_SCHEDULER_COMMAND", "warning",
				fmt.Sprintf("unknown scheduler command %q", command.Command)); !retry {
				return nt, k, pid
			}
			continue
		}
	}
}
