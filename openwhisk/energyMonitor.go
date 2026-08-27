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
// name is still empty, or genuinely absent from the map, the default
// is now to NOT enforce — the reverse of the previous "safe default is
// enforced" assumption, which had it backwards. A trace that runs
// unmonitored already has a safe, tested catch-all (committed_j
// credited uncapped at settlement, a dedicated [safety] log — CLAUDE.md
// §3.3). A NON_INTERRUPTIBLE action frozen or killed by mistake has no
// recovery path at all. Between under-enforcing a genuinely
// interruptible action and destroying a genuinely NON_INTERRUPTIBLE
// one, the former is the strictly safer failure mode. Should now be
// rare after the action_name fix above — every occurrence is logged as
// a critical [safety] incident (logUnresolvedInterruptionClass), not
// silently absorbed, since it signals the resolution mechanism itself
// failed, not an expected/accounted-for outcome.
func isNonInterruptibleForThisStep(energy *EnergyState) bool {
	if energy == nil || energy.InterruptionClass == nil {
		return false
	}
	class, ok := energy.InterruptionClass[energy.ResolvedActionName]
	if !ok || energy.ResolvedActionName == "" {
		logUnresolvedInterruptionClass(energy)
		return true
	}
	return class == "NON_INTERRUPTIBLE"
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
			"risk freezing/killing a NON_INTERRUPTIBLE action by mistake",
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

// shouldMonitorEnergy mirrors CLAUDE.md §7.2 and §3.3: a disabled or
// negative threshold, no energy state at all (§7.5's third case,
// energy==nil), or THIS step's action being NON_INTERRUPTIBLE all mean
// no threshold ENFORCEMENT loop — i.e. no freeze, no kill (§3.3:
// "aucun freeze énergétique, aucun kill énergétique"). Measurement
// itself is unaffected: runHandler.go's start/end readEnergy snapshots
// (§3.3's "mesure continue") run unconditionally, independent of this
// monitoring loop, so a NON_INTERRUPTIBLE step is still fully measured
// and reinjected into __energy_state even with no monitor goroutine.
func shouldMonitorEnergy(energy *EnergyState) bool {
	return energy != nil && energy.ExecutionThresholdJ > 0 && !isNonInterruptibleForThisStep(energy)
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
	requestedAt := time.Now()

	if err := proc.controller.freezeExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
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

	command, err := postExecutionPaused(event, energy.MaxPauseDurationMs)
	if err != nil {
		log.Printf(
			"[safety] EXECUTION_PAUSED channel call failed for trace=%s pause=%s: %v — "+
				"killing (cannot resume without a confirmed scheduler command).",
			energy.TraceID, pauseID, err,
		)
		if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
		}
		return 0, true, pauseID
	}

	if command.PauseID != pauseID {
		// CLAUDE.md §6.6: "Une commande avec un pause_id obsolète est
		// ignorée et loggée" — here that can only mean the scheduler's
		// answer does not correspond to the pause cycle we just opened;
		// there is no cycle left to resume into, so the safe response is
		// the same as an unreachable scheduler: kill.
		log.Printf(
			"[safety] scheduler command pause_id=%q does not match the active pause=%q "+
				"for trace=%s — stale/mismatched command, ignoring it and killing.",
			command.PauseID, pauseID, energy.TraceID,
		)
		if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
		}
		return 0, true, pauseID
	}

	switch command.Command {
	case "RESUME_EXECUTION":
		if err := proc.controller.resumeExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
			log.Printf("[safety] resumeExecution failed for trace=%s pause=%s: %v — killing.", energy.TraceID, pauseID, err)
			if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
				log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
			}
			return 0, true, pauseID
		}
		log.Printf(
			"[resume] trace=%s pause=%s resumed, new_threshold=%.4fJ",
			energy.TraceID, pauseID, command.NewExecutionThresholdJ,
		)
		return command.NewExecutionThresholdJ, false, pauseID
	case "KILL_EXECUTION":
		log.Printf("[energy_monitor] KILL_EXECUTION received for trace=%s pause=%s reason=%s", energy.TraceID, pauseID, command.Reason)
		if err := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); err != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, err)
		}
		return 0, true, pauseID
	default:
		log.Printf(
			"[safety] unknown scheduler command %q for trace=%s pause=%s — killing.",
			command.Command, energy.TraceID, pauseID,
		)
		if killErr := proc.controller.killExecution(energy.TraceID, energy.ReservationID, pauseID); killErr != nil {
			log.Printf("[energy_monitor] killExecution failed for trace=%s pause=%s: %v", energy.TraceID, pauseID, killErr)
		}
		return 0, true, pauseID
	}
}
