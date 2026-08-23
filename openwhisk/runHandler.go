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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ErrResponse is the response when there are errors
type ErrResponse struct {
	Error string `json:"error"`
}

func sendError(w http.ResponseWriter, code int, cause string) {
	errResponse := ErrResponse{Error: cause}
	b, err := json.Marshal(errResponse)
	if err != nil {
		b = []byte("error marshalling error response")
		Debug(err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
	w.Write([]byte("\n"))
}

// ExecutionKilledEvent is the EXECUTION_KILLED event (CLAUDE.md §7.6).
// PauseID is "" for a direct pauseEnabled=false kill (§3.1, no pause
// cycle ever happened) or non-empty when the kill followed a freeze
// cycle (PLAYBOOK.md Phase 7). As of this phase, the event is sent via
// the dedicated runtime -> scheduler channel (schedulerChannel.go's
// postExecutionKilled), fire-and-forget — no longer embedded in the
// /run HTTP response (PLAYBOOK.md Phase 7's resolved open question #2:
// that channel cannot carry a pause round-trip, since /run's caller is
// OpenWhisk itself, not the scheduler).
//
// ActionName (PLAYBOOK.md Phase 8) mirrors the field EXECUTION_PAUSED
// already carries (§7.6) — added to close a gap §7.6's original
// EXECUTION_KILLED shape left open: resolving compensation_sequence for
// a COMPENSATABLE kill (§6.7) requires knowing precisely WHICH action
// (component of the sequence, possibly not the first) was killed, and a
// sequence is dispatched as a single invoke_action() call the scheduler
// never sees the intermediate steps of (§2, "séquence") — without this
// field, the scheduler would have no way to learn it for a component
// killed directly (pauseEnabled=false, no preceding EXECUTION_PAUSED to
// remember it from).
type ExecutionKilledEvent struct {
	Event                   string                 `json:"event"`
	TraceID                 string                 `json:"trace_id"`
	ReservationID           string                 `json:"reservation_id"`
	PauseID                 string                 `json:"pause_id"`
	ActionName              string                 `json:"action_name"`
	ExecutionPhase          string                 `json:"execution_phase"`
	EnergyBudgetExceeded    bool                   `json:"energy_budget_exceeded"`
	EnergyConsumedJ         float64                `json:"energy_consumed_j"`
	EnergyOriginalArguments map[string]interface{} `json:"energy_original_arguments"`
}

type runRequest struct {
	ActivationID string                 `json:"activation_id"`
	Value        map[string]interface{} `json:"value"`
}

func (ap *ActionProxy) runHandler(w http.ResponseWriter, r *http.Request) {

	// --- Snapshots de début : timestamp, énergie et CPU pris simultanément ---
	start := time.Now().UnixNano()
	energyStart, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy start: %v", err)
	}
	// Le PID est stable pendant toute la durée de l'invocation
	var cpuStart CPUSnapshot
	if ap.theExecutor != nil {
		cpuStart = readCPUSnapshot(ap.theExecutor.Pid())
	}

	// parse the request
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		sendError(w, http.StatusBadRequest, fmt.Sprintf("Error reading request body: %v", err))
		return
	}
	Debug("done reading %d bytes", len(body))

	// check if you have an action
	if ap.theExecutor == nil {
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("no action defined yet"))
		return
	}

	if ap.theExecutor != nil {
		log.Printf("DEBUG executor pid=%d", ap.theExecutor.Pid())
		cpuStart = readCPUSnapshot(ap.theExecutor.Pid())
	}

	// check if the process exited
	if ap.theExecutor.Exited() {
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("command exited"))
		return
	}

	// extraire les métadonnées avant de supprimer les newlines
	var req runRequest
	meta := &RunMeta{PodName: os.Getenv("HOSTNAME")}
	var energyState *EnergyState
	if err := json.Unmarshal(body, &req); err == nil {
		meta.ActivationID = req.ActivationID
		if v, ok := req.Value["energy_trace_id"]; ok {
			meta.TraceID, _ = v.(string)
		}

		// Sidecar (CLAUDE.md §7.5, §7.8): strip energy_* (first step) or
		// __energy_state (later step) from the params before the business
		// code ever sees them, and re-encode the body accordingly. No-op
		// (energyState stays nil) when neither is present.
		var cleanedValue map[string]interface{}
		energyState, cleanedValue = ExtractEnergyState(req.Value)
		if energyState != nil {
			req.Value = cleanedValue
			if newBody, marshalErr := json.Marshal(req); marshalErr == nil {
				body = newBody
			} else {
				log.Printf("[energy_state] failed to re-encode body after stripping energy state: %v", marshalErr)
			}
		}
	}

	// remove newlines
	body = bytes.Replace(body, []byte("\n"), []byte(""), -1)

	// execute the action
	response, err, killInfo := ap.theExecutor.Interact(body, energyState)

	// Energy threshold reached (CLAUDE.md §3.1, §7.2): the process is
	// already dead, killed locally either synchronously (pauseEnabled=
	// false) or after a failed/refused pause cycle (PLAYBOOK.md Phase 7).
	// The EXECUTION_KILLED event (§7.6) is POSTed to the dedicated
	// runtime -> scheduler channel (schedulerChannel.go), fire-and-forget
	// — this /run response itself carries none of it (see below).
	if killInfo != nil {
		ap.theExecutor = nil // the process is dead; a fresh one is needed next time

		totalConsumedJ := killInfo.EnergyConsumedJ + energyState.ConsumedBeforeJ
		event := ExecutionKilledEvent{
			Event:                "EXECUTION_KILLED",
			TraceID:              energyState.TraceID,
			ReservationID:        energyState.ReservationID,
			PauseID:              killInfo.PauseID,
			ActionName:           actionNameForEvents(),
			ExecutionPhase:       energyState.ExecutionPhase,
			EnergyBudgetExceeded: true,
			EnergyConsumedJ:      totalConsumedJ,
			// Already stripped of energy_*/__energy_state above — the
			// business code never saw anything else either.
			EnergyOriginalArguments: req.Value,
		}

		// Record this activation's own measurement SYNCHRONOUSLY, and
		// BEFORE postExecutionKilled is ever dispatched (CLAUDE.md §6.9,
		// hardening phase point 2). postExecutionKilled() is itself
		// fire-and-forget (no confirmation awaited before sending), and
		// the scheduler's handle_execution_killed() queries
		// collector.get_energy_for_trace(trace_id) the MOMENT it receives
		// that event — with the ordinary async recordMetrics()
		// (fire-and-forget push to the collector, metrics_helpers.go),
		// nothing guaranteed this write had landed before that query ran:
		// two independent fire-and-forget operations racing with no
		// synchronization between them, a real risk of the scheduler
		// settling on an incomplete measurement, not a theoretical one.
		// recordMetricsSync blocks until the push actually completes.
		ap.recordMetricsSync("/run", start, energyStart, cpuStart, meta)

		// Fire-and-forget over the dedicated channel (CLAUDE.md §3.1: must
		// never block this response — a synchronous call could stall for
		// up to postExecutionKilled's own timeout on a network hiccup) —
		// but only AFTER the line above has already guaranteed the
		// measurement it depends on is safely recorded.
		// Original arguments travel ONLY over this channel, never in the
		// /run response nor in logs by default (CLAUDE.md §7.6).
		go postExecutionKilled(event)

		log.Printf(
			"[energy_monitor] EXECUTION_KILLED trace=%s reservation=%s pause=%s phase=%s energy_consumed_j=%.4f",
			event.TraceID, event.ReservationID, event.PauseID, event.ExecutionPhase, event.EnergyConsumedJ,
		)

		// The /run response is now a neutral failure marker for
		// OpenWhisk's own orchestration (it must not chain to a next
		// sequence step or report success upstream) — the scheduler
		// learns the real, authoritative outcome from the channel event
		// above, never from this body (PLAYBOOK.md Phase 7's resolved
		// open question #2).
		sendError(w, http.StatusBadRequest, "energy budget exceeded: action killed")
		return
	}

	// check for early termination
	if err != nil {
		Debug("WARNING! Command exited")
		ap.theExecutor = nil
		sendError(w, http.StatusBadRequest, fmt.Sprintf("command exited"))
		return
	}
	DebugLimit("received:", response, 120)

	// check if the answer is an object map
	var objmap map[string]*json.RawMessage
	var objarray []interface{}
	err = json.Unmarshal(response, &objmap)
	if err != nil {
		err = json.Unmarshal(response, &objarray)
		if err != nil {
			sendError(w, http.StatusBadGateway, "The action did not return a dictionary or array.")
			return
		}
	}

	// Sidecar reinjection (CLAUDE.md §7.8): only when this invocation
	// actually carried an energy state, and only when the business result
	// is an object (there is nowhere to attach a hidden field to an
	// array). Measured via the same RAPL/cgroup primitives recordMetrics
	// uses below — a second, independent read, since the value is needed
	// here (before the response is written) rather than at the end of
	// this handler. No attempt is made to detect the sequence's last
	// step (§7.8 point 4): every step gets __energy_state reinjected.
	if energyState != nil && objmap != nil {
		stepEnergyEnd, energyErr := readEnergy()
		if energyErr != nil {
			log.Printf("readEnergy (sidecar) end: %v", energyErr)
		}
		var stepCPUEnd CPUSnapshot
		if ap.theExecutor != nil {
			stepCPUEnd = readCPUSnapshot(ap.theExecutor.Pid())
		}
		measuredJ := float64(attributedEnergyUJ(energyStart, stepEnergyEnd, cpuStart, stepCPUEnd)) / 1e6

		updatedObjmap, reinjectErr := ReinjectEnergyState(objmap, energyState, measuredJ)
		if reinjectErr != nil {
			log.Printf("[energy_state] failed to reinject energy state: %v", reinjectErr)
		} else if newResponse, marshalErr := json.Marshal(updatedObjmap); marshalErr == nil {
			objmap = updatedObjmap
			response = newResponse
		} else {
			log.Printf("[energy_state] failed to re-encode response after reinjecting energy state: %v", marshalErr)
		}
	}

	// --- Enregistrement des métriques avec pondération CPU (CLAUDE.md
	// §6.9 hardening pass, point 3) ---
	//
	// recordMetricsSync, BEFORE the /run response is written — mirrors
	// the EXECUTION_KILLED path's own fix (point 2): whatever reads this
	// activation's measurement right after invoke_action() returns (the
	// scheduler's own settle_forward(), via collector.get_energy_for_trace())
	// must not race an async push with no ordering guarantee. The window
	// here is smaller than the kill path's (OpenWhisk's own activation
	// processing adds real indirection between this handler's response
	// and the scheduler ever seeing it), but "smaller" is not "zero" —
	// the ordinary async recordMetrics() (fire-and-forget `go
	// pushMetrics(...)`, metrics_helpers.go) gave no actual guarantee
	// either way.
	ap.recordMetricsSync("/run", start, energyStart, cpuStart, meta)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
	numBytesWritten, err := w.Write(response)

	// flush output
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// diagnostic when you have writing problems
	if err != nil {
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("Error writing response: %v", err))
		return
	}
	if numBytesWritten != len(response) {
		sendError(w, http.StatusInternalServerError, fmt.Sprintf("Only wrote %d of %d bytes to response", numBytesWritten, len(response)))
		return
	}
}
