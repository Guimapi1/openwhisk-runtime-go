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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawMessageMap round-trips m through JSON into the map[string]*json.RawMessage
// shape runHandler.go already parses action results into, so tests exercise
// the exact type ReinjectEnergyState is meant to operate on.
func rawMessageMap(t *testing.T, m map[string]interface{}) map[string]*json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(m)
	require.NoError(t, err)
	var out map[string]*json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &out))
	return out
}

// 1. First step: energy_* fields read from the direct body, stripped
// before the (simulated) business code is invoked.
func TestExtractEnergyState_FirstStepReadsDirectEnergyParams(t *testing.T) {
	params := map[string]interface{}{
		"name":                         "Alice",
		"quantity":                     float64(3),
		"energy_trace_id":              "trace-123",
		"energy_reservation_id":        "trace-123",
		"energy_execution_phase":       "forward",
		"energy_execution_threshold_j": 55.0,
		"energy_consumed_before_j":     10.0,
		"energy_pause_enabled":         true,
		"energy_pause_mode":            "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": float64(500),
		"energy_max_pause_count":       float64(1),
		"energy_interruption_class":    "COMPENSATABLE",
	}

	state, cleaned := ExtractEnergyState(params)

	require.NotNil(t, state)
	assert.Equal(t, "trace-123", state.TraceID)
	assert.Equal(t, "trace-123", state.ReservationID)
	assert.Equal(t, "forward", state.ExecutionPhase)
	assert.Equal(t, 55.0, state.ExecutionThresholdJ)
	assert.Equal(t, 10.0, state.ConsumedBeforeJ)
	assert.True(t, state.PauseEnabled)
	assert.Equal(t, "CGROUP_FREEZE", state.PauseMode)
	assert.Equal(t, int64(500), state.MaxPauseDurationMs)
	assert.Equal(t, int64(1), state.MaxPauseCount)
	assert.Equal(t, "COMPENSATABLE", state.InterruptionClass)

	// The simulated business code only ever sees `cleaned` — verify it
	// never receives any energy_* key.
	simulatedBusinessCodeParams := cleaned
	assert.Equal(t, map[string]interface{}{"name": "Alice", "quantity": float64(3)}, simulatedBusinessCodeParams)
	for paramKey := range energyParamKeys {
		_, present := simulatedBusinessCodeParams[paramKey]
		assert.False(t, present, "business code must never see %s", paramKey)
	}
	_, hasHiddenState := simulatedBusinessCodeParams[energyStateKey]
	assert.False(t, hasHiddenState, "business code must never see %s", energyStateKey)
}

// 2. Subsequent step: fields read from __energy_state, which itself (and
// every energy_* key) is absent from what the business code receives.
func TestExtractEnergyState_SubsequentStepReadsHiddenState(t *testing.T) {
	hiddenState := map[string]interface{}{
		"trace_id":              "trace-456",
		"reservation_id":        "trace-456",
		"execution_phase":       "forward",
		"execution_threshold_j": 73.3,
		"consumed_before_j":     56.2,
		"pause_enabled":         true,
		"pause_mode":            "CGROUP_FREEZE",
		"max_pause_duration_ms": float64(500),
		"max_pause_count":       float64(1),
		"interruption_class":    "COMPENSATABLE",
	}
	params := map[string]interface{}{
		"quantity":     float64(3),
		energyStateKey: hiddenState,
	}

	state, cleaned := ExtractEnergyState(params)

	require.NotNil(t, state)
	assert.Equal(t, "trace-456", state.TraceID)
	assert.Equal(t, "trace-456", state.ReservationID)
	assert.Equal(t, 73.3, state.ExecutionThresholdJ)
	assert.Equal(t, 56.2, state.ConsumedBeforeJ)

	assert.Equal(t, map[string]interface{}{"quantity": float64(3)}, cleaned)
	_, hasHiddenState := cleaned[energyStateKey]
	assert.False(t, hasHiddenState, "business code must never see %s", energyStateKey)
}

// 3. Neither present: no energy state extracted, business code receives
// its original parameters unchanged (equivalent to a disabled threshold,
// §7.2).
func TestExtractEnergyState_NeitherPresentLeavesParamsUnchanged(t *testing.T) {
	params := map[string]interface{}{"x": 1.0, "y": "z", "nested": map[string]interface{}{"a": true}}

	state, cleaned := ExtractEnergyState(params)

	assert.Nil(t, state)
	assert.Equal(t, params, cleaned)
}

// 4. Reinjection: the returned result carries an up-to-date
// __energy_state with consumed_before_j incremented by the energy
// measured during this step.
func TestReinjectEnergyState_IncrementsConsumedBeforeJ(t *testing.T) {
	previous := &EnergyState{
		TraceID:             "trace-1",
		ReservationID:       "trace-1",
		ExecutionPhase:      "forward",
		ExecutionThresholdJ: 80.0,
		ConsumedBeforeJ:     10.0,
		PauseEnabled:        true,
		PauseMode:           "CGROUP_FREEZE",
		MaxPauseDurationMs:  500,
		MaxPauseCount:       1,
		InterruptionClass:   "COMPENSATABLE",
	}
	result := rawMessageMap(t, map[string]interface{}{"status": "ok"})

	updated, err := ReinjectEnergyState(result, previous, 12.5)
	require.NoError(t, err)

	rawState, ok := updated[energyStateKey]
	require.True(t, ok, "%s must be present in the reinjected result", energyStateKey)
	var got EnergyState
	require.NoError(t, json.Unmarshal(*rawState, &got))

	assert.Equal(t, 22.5, got.ConsumedBeforeJ) // 10.0 + 12.5
	assert.Equal(t, previous.TraceID, got.TraceID)
	assert.Equal(t, previous.ReservationID, got.ReservationID)
	assert.Equal(t, previous.ExecutionThresholdJ, got.ExecutionThresholdJ)
	assert.Equal(t, previous.InterruptionClass, got.InterruptionClass)
}

// ReinjectEnergyState with no prior state (§7.2 disabled-threshold
// equivalent) must leave the result untouched.
func TestReinjectEnergyState_NoPriorStateLeavesResultUnchanged(t *testing.T) {
	result := rawMessageMap(t, map[string]interface{}{"status": "ok"})

	updated, err := ReinjectEnergyState(result, nil, 5.0)

	require.NoError(t, err)
	assert.Equal(t, result, updated)
}

// 5. The business result itself (outside __energy_state) is never
// altered — an arbitrary result with nested dicts and varied types
// survives byte-for-byte, with only __energy_state added.
func TestReinjectEnergyState_LeavesBusinessResultByteForByteUntouched(t *testing.T) {
	businessResult := map[string]interface{}{
		"status": "ok",
		"count":  42,
		"ratio":  3.14159265358979,
		"nested": map[string]interface{}{
			"a": []interface{}{1, 2, 3},
			"b": nil,
			"c": true,
		},
		"list": []interface{}{"x", "y", map[string]interface{}{"z": 1}},
	}
	original := rawMessageMap(t, businessResult)
	originalBytes := make(map[string]string, len(original))
	for k, v := range original {
		originalBytes[k] = string(*v)
	}

	previous := &EnergyState{TraceID: "t", ConsumedBeforeJ: 1.0}
	updated, err := ReinjectEnergyState(original, previous, 2.0)
	require.NoError(t, err)

	for k, wantBytes := range originalBytes {
		gotRaw, ok := updated[k]
		require.True(t, ok, "key %s missing after reinjection", k)
		assert.Equal(t, wantBytes, string(*gotRaw), "key %s was altered by reinjection", k)
	}

	assert.Len(t, updated, len(original)+1, "only __energy_state should have been added")
	_, hasState := updated[energyStateKey]
	assert.True(t, hasState)

	// The input map itself must not have been mutated.
	assert.Len(t, original, len(businessResult))
	_, hadStateBefore := original[energyStateKey]
	assert.False(t, hadStateBefore)
}
