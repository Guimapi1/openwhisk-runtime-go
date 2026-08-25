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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunHandler_MultiStepSequence_TraceIDPropagatesToEveryStepsMetric is a
// regression test for a real bug found via manual cluster investigation:
// runHandler.go populated meta.TraceID ONLY from the raw top-level
// "energy_trace_id" param, which OpenWhisk's native sequence chaining only
// ever supplies to a sequence's FIRST step (CLAUDE.md §7.8) — every
// following step's own metrics.Entry.TraceID silently stayed "", making
// that step's own energy contribution invisible to any trace_id-scoped
// collector query, even though the runtime's OWN internal accumulator
// (__energy_state.consumed_before_j) kept tracking the correct running
// total the whole time. The bug hid behind a passing single-step test
// (TestRunHandler_SidecarWiring_StripsEnergyParamsAndReinjectsState) because
// that test only ever exercises a first step.
//
// This test drives the REAL runHandler.go HTTP pipeline (no mocked
// extraction/recording) across two steps of a simulated sequence:
//  1. a first step, carrying "energy_trace_id" at the top level, exactly as
//     the scheduler sends it (CLAUDE.md §6.4);
//  2. a second step, carrying ONLY the "__energy_state" sidecar produced by
//     step 1's own response — exactly what OpenWhisk's native sequence
//     chaining feeds forward as the next step's raw input (CLAUDE.md §7.8),
//     with no top-level energy_* param of its own.
//
// It then reads back ap.metrics (the exact in-process store recordMetricsSync
// populates before every /run response, metrics_helpers.go) and asserts BOTH
// steps' Entry.TraceID equal the original trace_id — not just the first
// step's.
func TestRunHandler_MultiStepSequence_TraceIDPropagatesToEveryStepsMetric(t *testing.T) {
	os.RemoveAll("./action/energy_sidecar_multistep")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_sidecar_multistep", "", logf, logf)

	// Echoes back the exact line it read on stdin, wrapped so it stays a
	// valid single JSON object (same fake action as
	// energy_state_integration_test.go).
	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	const traceID = "trace-multistep-xyz"

	// Step 1: first step of the sequence — energy_trace_id supplied at the
	// top level by the scheduler.
	step1Body := fmt.Sprintf(`{"value": {
		"quantity": 3,
		"energy_trace_id": %q,
		"energy_reservation_id": %q,
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 55.0,
		"energy_consumed_before_j": 0.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 500,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"reserve_stock": "COMPENSATABLE"}
	}}`, traceID, traceID)

	resp1, status1, err := doPost(ts.URL+"/run", step1Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status1)

	var parsed1 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp1), &parsed1))
	stateRaw, ok := parsed1[energyStateKey]
	require.True(t, ok, "step 1 response must carry %s: %s", energyStateKey, resp1)

	stateJSON, err := json.Marshal(stateRaw)
	require.NoError(t, err)

	// Step 2: a non-first step — NO top-level energy_trace_id, exactly as a
	// real OpenWhisk sequence hands step 1's own result (business fields +
	// __energy_state) forward as step 2's raw input value (CLAUDE.md §7.8).
	step2Body := fmt.Sprintf(`{"value": {"quantity": 5, %q: %s}}`, energyStateKey, string(stateJSON))

	resp2, status2, err := doPost(ts.URL+"/run", step2Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status2)

	var parsed2 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp2), &parsed2))
	_, ok = parsed2[energyStateKey]
	require.True(t, ok, "step 2 response must ALSO carry %s: %s", energyStateKey, resp2)

	// The decisive assertion: BOTH steps' own contribution must be tagged
	// with the SAME trace_id in the collector-bound metrics store
	// (metricHandler.go's Entry, populated synchronously by
	// recordMetricsSync before either /run response was written). Before
	// the fix, entries[1].TraceID was "" — step 2's energy was silently
	// invisible to any trace_id-scoped /query.
	snap := ap.metrics.Snapshot()
	entries := snap["/run"]
	require.Len(t, entries, 2, "expected exactly one /run metrics entry per step")
	assert.Equal(t, traceID, entries[0].TraceID, "step 1 (first step) must be tagged")
	assert.Equal(t, traceID, entries[1].TraceID,
		"step 2 (non-first step, energy state only via __energy_state) must ALSO be "+
			"tagged with the same trace_id — this is exactly what the meta.TraceID bug broke")
}
