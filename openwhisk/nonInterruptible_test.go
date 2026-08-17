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

// nonInterruptible_test.go: PLAYBOOK.md Phase 10, CLAUDE.md §3.3. Unlike
// KILL_SAFE/COMPENSATABLE (executor_test.go, pauseResume_test.go), a
// NON_INTERRUPTIBLE step must receive NEITHER a freeze NOR a kill no
// matter how far past its threshold it runs — enforcement is entirely
// disabled for this class, measurement is not (§7.9's "mesure continue"
// is delivered by runHandler.go's unconditional start/end readEnergy
// snapshots, independent of shouldMonitorEnergy's loop).
//
// Both fixtures below set energy_consumed_before_j already at/above
// energy_execution_threshold_j (the same determinism trick as
// executor_test.go's header comment) specifically so that, had
// enforcement NOT been disabled, the very first monitor tick would have
// triggered a freeze or a kill — making "nothing happened" a meaningful,
// non-vacuous assertion.

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 1. A NON_INTERRUPTIBLE action that exceeds its reservation is neither
// frozen (pause_enabled=true, so a freeze would otherwise be attempted)
// nor killed — it runs to natural termination.
func TestRunHandler_EnergyMonitor_NonInterruptible_NeverFreezesOrKills(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	t.Setenv("__OW_ACTION_NAME", "long_running_step")
	fs := newFakeSchedulerServer(t)
	// If the runtime ever tried to freeze this step, the fake scheduler
	// would grant a resume — which would make a bug (enforcement wrongly
	// applied) look like a passing test instead of a hang. Asserting
	// zero paused/killed events below is what actually catches it.
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: 1e9,
		}
	})

	os.RemoveAll("./action/energy_noninterruptible")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_noninterruptible", "", logf, logf)

	// Sleeps briefly (long enough for several monitor ticks to have a
	// chance to fire, at ENERGY_MONITOR_INTERVAL_MS=10) then responds
	// normally — if enforcement were wrongly active, this process would
	// never get the chance to reach its own response.
	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"energy_trace_id": "trace-noninterruptible",
		"energy_reservation_id": "trace-noninterruptible",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"long_running_step": "NON_INTERRUPTIBLE"}
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"], "the action must reach its own natural termination: %s", resp)

	// Give any wrongly-fired async event a moment to land before
	// asserting its absence.
	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, fs.getPausedEvents(), "a NON_INTERRUPTIBLE step must never be frozen (§3.3)")
	assert.Empty(t, fs.getKilledEvents(), "a NON_INTERRUPTIBLE step must never be killed (§3.3)")

	// Still measured (§3.3 "mesure continue", §7.9): __energy_state
	// carries an up-to-date consumed_before_j despite no enforcement.
	stateRaw, ok := parsed[energyStateKey]
	require.True(t, ok, "%s must still be present: %s", energyStateKey, resp)
	stateMap, ok := stateRaw.(map[string]interface{})
	require.True(t, ok)
	consumedBefore, ok := stateMap["consumed_before_j"].(float64)
	require.True(t, ok)
	assert.True(t, consumedBefore >= 1.0, "measurement must still have happened: %v", consumedBefore)
}

// 5. In a two-step sequence (KILL_SAFE then NON_INTERRUPTIBLE, sharing
// one per-component interruption_class map, PLAYBOOK.md Phase 10), only
// the NON_INTERRUPTIBLE step escapes enforcement — the KILL_SAFE step
// remains subject to immediate kill on exceeding its own threshold. Each
// step is simulated as its own action-container process (as it would be
// in a real native OpenWhisk sequence), distinguished purely by
// __OW_ACTION_NAME, resolving its OWN entry in the shared map — never a
// registry lookup (§7.1).
func TestRunHandler_EnergyMonitor_MixedSequence_OnlyNonInterruptibleStepEscapesEnforcement(t *testing.T) {
	sharedInterruptionClass := `{"step_kill_safe": "KILL_SAFE", "step_non_interruptible": "NON_INTERRUPTIBLE"}`

	t.Run("first step: KILL_SAFE remains enforced", func(t *testing.T) {
		t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
		t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
		t.Setenv("__OW_ACTION_NAME", "step_kill_safe")
		fs := newFakeSchedulerServer(t)

		os.RemoveAll("./action/energy_mixed_seq_kill_safe")
		logf, err := ioutil.TempFile("/tmp", "log")
		require.NoError(t, err)
		ap := NewActionProxy("./action/energy_mixed_seq_kill_safe", "", logf, logf)

		// Never responds on its own: only a correctly-enforced kill can
		// end this request quickly.
		script := []byte("#!/bin/sh\nwhile read a; do sleep 30; done\n")
		_, err = ap.ExtractAction(&script, "bin")
		require.NoError(t, err)
		require.NoError(t, ap.StartLatestAction())

		ts := httptest.NewServer(ap)
		defer ts.Close()

		requestBody := `{"value": {
			"energy_trace_id": "trace-mixed-seq",
			"energy_reservation_id": "trace-mixed-seq",
			"energy_execution_phase": "forward",
			"energy_execution_threshold_j": 1.0,
			"energy_consumed_before_j": 1.0,
			"energy_pause_enabled": false,
			"energy_pause_mode": "",
			"energy_max_pause_duration_ms": 0,
			"energy_max_pause_count": 0,
			"energy_interruption_class": ` + sharedInterruptionClass + `
		}}`

		_, status, err := doPost(ts.URL+"/run", requestBody)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)

		waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered for the KILL_SAFE step", func() bool {
			return len(fs.getKilledEvents()) == 1
		})
		assert.Equal(t, "trace-mixed-seq", fs.getKilledEvents()[0].TraceID)
	})

	t.Run("second step: NON_INTERRUPTIBLE escapes enforcement", func(t *testing.T) {
		t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
		t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
		t.Setenv("__OW_ACTION_NAME", "step_non_interruptible")
		fs := newFakeSchedulerServer(t)

		os.RemoveAll("./action/energy_mixed_seq_non_interruptible")
		logf, err := ioutil.TempFile("/tmp", "log")
		require.NoError(t, err)
		ap := NewActionProxy("./action/energy_mixed_seq_non_interruptible", "", logf, logf)

		script := []byte(sleepThenRespondScriptContent("0.3"))
		_, err = ap.ExtractAction(&script, "bin")
		require.NoError(t, err)
		require.NoError(t, ap.StartLatestAction())
		defer ap.theExecutor.Stop()

		ts := httptest.NewServer(ap)
		defer ts.Close()

		// Same shared map, same threshold/consumed_before shape as the
		// KILL_SAFE step above — only __OW_ACTION_NAME differs, proving
		// the runtime resolves ITS OWN entry rather than e.g. always
		// picking the first (or only) map entry.
		requestBody := `{"value": {
			"__energy_state": {
				"trace_id": "trace-mixed-seq",
				"reservation_id": "trace-mixed-seq",
				"execution_phase": "forward",
				"execution_threshold_j": 1.0,
				"consumed_before_j": 1.0,
				"pause_enabled": false,
				"pause_mode": "",
				"max_pause_duration_ms": 0,
				"max_pause_count": 0,
				"interruption_class": ` + sharedInterruptionClass + `
			}
		}}`

		resp, status, err := doPost(ts.URL+"/run", requestBody)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, "resp=%s", resp)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
		assert.Equal(t, true, parsed["ok"])

		time.Sleep(50 * time.Millisecond)
		assert.Empty(t, fs.getKilledEvents(), "the NON_INTERRUPTIBLE step must not be killed")
		assert.Empty(t, fs.getPausedEvents(), "the NON_INTERRUPTIBLE step must not be frozen")
	})
}
