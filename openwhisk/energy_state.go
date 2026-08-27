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
)

// energy_state.go implements the sidecar mechanism described in CLAUDE.md
// §7.8: how the energy state travels from one step of a native OpenWhisk
// sequence to the next. It does NOT decide anything about thresholds,
// freezing or pausing (later phases) — it only carries state.
//
// ASSUMPTION (CLAUDE.md §7.8, §9): this mechanism relies on OpenWhisk
// preserving an arbitrary JSON field ("__energy_state") in an action's
// result, unmodified, when that result becomes the next step's input
// during native sequence chaining. Empirically confirmed 2026-08-12
// against the live cluster (paradoxe-56.rennes.grid5000.fr): a two-action
// native sequence (`wsk action create seq --sequence A,B`), where A's
// result included an undocumented "__unexpected_probe" field, delivered
// that field byte-for-byte into B's input params. Test actions were
// deployed, verified, and deleted; no fixture from that run is checked
// into this repo.

// energyStateKey is the hidden field name the runtime uses to carry the
// energy state between two steps of the same native sequence. Never
// visible to, or writable by, the developer's business code.
const energyStateKey = "__energy_state"

// energyParamKeys maps each energy_* parameter key (CLAUDE.md §7.5, sent
// by the scheduler only to the first step) to the bare field name used
// inside __energy_state (CLAUDE.md §2). Both representations decode into
// the same EnergyState struct via the JSON tags below.
var energyParamKeys = map[string]string{
	"energy_trace_id":              "trace_id",
	"energy_reservation_id":        "reservation_id",
	"energy_execution_phase":       "execution_phase",
	"energy_execution_threshold_j": "execution_threshold_j",
	"energy_consumed_before_j":     "consumed_before_j",
	"energy_pause_enabled":         "pause_enabled",
	"energy_pause_mode":            "pause_mode",
	"energy_max_pause_duration_ms": "max_pause_duration_ms",
	"energy_max_pause_count":       "max_pause_count",
	"energy_interruption_class":    "interruption_class",
}

// firstStepAnchorKey is the one energy_* key whose presence marks this
// invocation as the first step of a sequence (or a standalone action) —
// same anchor runHandler.go already used for trace ID extraction before
// this file existed.
const firstStepAnchorKey = "energy_trace_id"

// EnergyState is the energy bookkeeping carried between sequence steps
// (CLAUDE.md §2 "__energy_state", §7.5's energy_* fields). JSON tags use
// the bare (non "energy_"-prefixed) names, matching __energy_state's own
// shape on the wire.
//
// InterruptionClass (PLAYBOOK.md Phase 10) is a PER-COMPONENT map
// ({action_name: interruption_class}) for the whole sequence, not a
// single string — CLAUDE.md §6.4's original design ("energy_interruption_class
// est envoyé... mais le runtime ne l'utilise pas pour choisir le
// fallback") only ever carried the HEAD component's own class, correct
// only for a single-component trace: ReinjectEnergyState copies the
// WHOLE previous EnergyState forward unchanged except ConsumedBeforeJ,
// so a non-head step would otherwise see the HEAD's class, never its
// own. A sequence mixing KILL_SAFE and NON_INTERRUPTIBLE components
// (§3.3) needs each step's runtime to resolve ITS OWN entry — via
// ResolvedActionName below, see energyMonitor.go's
// isNonInterruptibleForThisStep — since it has no registry access of
// its own (§7.1). The map itself is immutable for the whole trace, so
// it needs no per-step update in ReinjectEnergyState, unlike
// ConsumedBeforeJ.
type EnergyState struct {
	TraceID             string            `json:"trace_id"`
	ReservationID       string            `json:"reservation_id"`
	ExecutionPhase      string            `json:"execution_phase"`
	ExecutionThresholdJ float64           `json:"execution_threshold_j"`
	ConsumedBeforeJ     float64           `json:"consumed_before_j"`
	PauseEnabled        bool              `json:"pause_enabled"`
	PauseMode           string            `json:"pause_mode"`
	MaxPauseDurationMs  int64             `json:"max_pause_duration_ms"`
	MaxPauseCount       int64             `json:"max_pause_count"`
	InterruptionClass   map[string]string `json:"interruption_class"`
	// ResolvedActionName: THIS step's own action name, short-normalized
	// (shortActionName(), energyMonitor.go) from OpenWhisk's own
	// per-activation /run payload (runHandler.go decodes it from
	// runRequest.ActionName, docs/ACTION.md's documented, always-present
	// "action_name" field) — NOT from __OW_ACTION_NAME, which is never
	// set in this proxy's own process (only in the child action's own
	// environment, derived by the language layer from this same
	// payload). Deliberately excluded from the wire format (json:"-"):
	// it is step-local, recomputed fresh by each step's own
	// runHandler.go from ITS OWN /run payload — never something to
	// carry across __energy_state's sidecar chaining, unlike every
	// other field above.
	ResolvedActionName string `json:"-"`
}

// decodeEnergyStateMap round-trips a generic map through JSON into an
// EnergyState, reusing the struct's tags as the single source of truth
// for field names instead of hand-writing two parallel type-assertion
// paths (one for the energy_* params, one for __energy_state).
func decodeEnergyStateMap(m map[string]interface{}) (*EnergyState, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var state EnergyState
	if err := json.Unmarshal(encoded, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ExtractEnergyState reads and strips the energy bookkeeping out of the
// parameters an action is about to receive (CLAUDE.md §7.5, §7.8):
//
//   - if energy_* keys are present directly in params, this is the first
//     step of a sequence (or a standalone action) — the state comes from
//     the scheduler;
//   - else if __energy_state is present, this is a later step — the state
//     comes from the previous step's reinjection;
//   - else there is no energy state at all, equivalent to a disabled
//     threshold (§7.2): (nil, params unchanged).
//
// In every case, the returned params map never contains any energy_* key
// nor __energy_state — the business code must never see this plumbing.
// The input map is never mutated; a shallow copy is returned.
func ExtractEnergyState(params map[string]interface{}) (*EnergyState, map[string]interface{}) {
	cleaned := make(map[string]interface{}, len(params))
	for k, v := range params {
		cleaned[k] = v
	}

	if _, present := cleaned[firstStepAnchorKey]; present {
		bare := make(map[string]interface{}, len(energyParamKeys))
		for paramKey, bareKey := range energyParamKeys {
			if v, ok := cleaned[paramKey]; ok {
				bare[bareKey] = v
			}
			delete(cleaned, paramKey)
		}
		state, err := decodeEnergyStateMap(bare)
		if err != nil {
			log.Printf("[energy_state] failed to decode energy_* params: %v", err)
			return nil, cleaned
		}
		return state, cleaned
	}

	if raw, present := cleaned[energyStateKey]; present {
		delete(cleaned, energyStateKey)
		asMap, ok := raw.(map[string]interface{})
		if !ok {
			logCorruptedEnergyState(fmt.Sprintf("%s present but not a JSON object (%T)", energyStateKey, raw))
			return nil, cleaned
		}
		state, err := decodeEnergyStateMap(asMap)
		if err != nil {
			logCorruptedEnergyState(fmt.Sprintf("failed to decode %s: %v", energyStateKey, err))
			return nil, cleaned
		}
		return state, cleaned
	}

	return nil, cleaned
}

// logCorruptedEnergyState (CLAUDE.md §6.9, hardening phase, project-
// specific case): __energy_state present but corrupted on a step that is
// NOT the sequence's first (the first step never reaches this branch —
// it reads energy_* directly, see firstStepAnchorKey above) means
// OpenWhisk's own sequence-chaining propagation (§7.8, empirically
// verified against a live cluster, see this file's own header) was
// somehow defeated for this one invocation — the exact assumption the
// whole sidecar mechanism depends on. The degraded behaviour itself is
// already correct (nil state -> §7.2's disabled-threshold path,
// monitoring without enforcement, exactly as absent __energy_state would
// be) — what was missing was the SEVERITY: this must be a first-order
// [safety] incident, not a routine [energy_state] log, because it means
// the energy guarantee is no longer assured for this specific step.
func logCorruptedEnergyState(reason string) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":  "ENERGY_STATE_CORRUPTED",
		"reason": reason,
	})
	if err != nil {
		log.Printf("[safety] __energy_state corrupted: %s (failed to marshal structured event: %v)", reason, err)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// ReinjectEnergyState adds an up-to-date __energy_state into a step's
// business result (CLAUDE.md §7.8), incrementing consumed_before_j by the
// energy measured for this step (via the existing RAPL/cgroup primitives,
// see attributedEnergyUJ in metrics_helpers.go — the caller is
// responsible for that measurement, this function just carries the
// number). Every other key of `result` is passed through as untouched raw
// bytes — this function never re-serializes the business result itself,
// so no reformatting (number precision, key order) can leak in.
//
// previous == nil means there was no energy state to begin with (§7.2
// disabled-threshold case): result is returned unchanged.
//
// This phase reinjects unconditionally on every step, with no attempt to
// detect "last step of the sequence" — CLAUDE.md §7.8 point 4 explicitly
// defers that question (who strips __energy_state from the FINAL result
// before it reaches the scheduler) to a later phase, once the full
// round-trip (pause/extension, phase 7) is designed. A step's runtime has
// no reliable native signal telling it whether it is the sequence's last
// action, so inventing a detection heuristic here would be exactly the
// kind of unlogged, silent decision CLAUDE.md warns against.
func ReinjectEnergyState(
	result map[string]*json.RawMessage, previous *EnergyState, measuredEnergyJ float64,
) (map[string]*json.RawMessage, error) {
	if previous == nil {
		return result, nil
	}

	updated := *previous
	updated.ConsumedBeforeJ += measuredEnergyJ

	encoded, err := json.Marshal(updated)
	if err != nil {
		return result, err
	}
	raw := json.RawMessage(encoded)

	out := make(map[string]*json.RawMessage, len(result)+1)
	for k, v := range result {
		out[k] = v
	}
	out[energyStateKey] = &raw
	return out, nil
}
