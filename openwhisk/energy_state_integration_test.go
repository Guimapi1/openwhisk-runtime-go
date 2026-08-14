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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunHandler_SidecarWiring exercises the actual runHandler.go wiring
// (not just the pure ExtractEnergyState/ReinjectEnergyState functions) end
// to end against a real subprocess "action": a trivial shell script that
// echoes back whatever raw body it received. This proves, at the level
// runHandler.go itself controls:
//  1. the energy_* keys never reach the business code (the subprocess), and
//  2. the HTTP response carries an up-to-date __energy_state.
//
// This does NOT exercise real OpenWhisk sequence chaining — it only
// proves this runtime's own half of the mechanism behaves as CLAUDE.md
// §7.5/§7.8 describe. The other half (does OpenWhisk itself preserve an
// action's `__energy_state` key across a native sequence's step
// boundary) was checked separately, empirically, against a live cluster
// (see energy_state.go's header) — no OpenWhisk deployment is reachable
// from this repo's own test environment, so it can't be exercised here
// as an automated test.
func TestRunHandler_SidecarWiring_StripsEnergyParamsAndReinjectsState(t *testing.T) {
	os.RemoveAll("./action/energy_sidecar")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_sidecar", "", logf, logf)

	// Echoes back the exact line it read on stdin, wrapped so it stays a
	// valid single JSON object: {"received_body": <raw body runHandler
	// handed to the executor>}.
	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"quantity": 3,
		"energy_trace_id": "trace-xyz",
		"energy_reservation_id": "trace-xyz",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 55.0,
		"energy_consumed_before_j": 10.0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 500,
		"energy_max_pause_count": 1,
		"energy_interruption_class": "COMPENSATABLE"
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))

	// 1. The subprocess (business code) never saw any energy_* key: the
	// only thing left in "value" is the actual business parameter.
	receivedBody, ok := parsed["received_body"].(map[string]interface{})
	require.True(t, ok, "action did not echo back a JSON object: %s", resp)
	receivedValue, ok := receivedBody["value"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, map[string]interface{}{"quantity": float64(3)}, receivedValue)

	// 2. The HTTP response carries an up-to-date __energy_state.
	stateRaw, ok := parsed[energyStateKey]
	require.True(t, ok, "response must carry %s: %s", energyStateKey, resp)
	stateMap, ok := stateRaw.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "trace-xyz", stateMap["trace_id"])
	assert.Equal(t, "trace-xyz", stateMap["reservation_id"])
	assert.Equal(t, "COMPENSATABLE", stateMap["interruption_class"])
	consumedBefore, ok := stateMap["consumed_before_j"].(float64)
	require.True(t, ok)
	// >= original consumed_before_j: the step's measured energy is added
	// on top, and is >= 0 even where RAPL is unavailable (sandboxed CI —
	// attributedEnergyUJ then returns 0, see metrics_helpers.go). testify
	// v1.3.0 (pinned by this repo) has no GreaterOrEqual, hence the
	// explicit comparison.
	assert.True(t, consumedBefore >= 10.0, "consumed_before_j went backwards: %v", consumedBefore)
}
