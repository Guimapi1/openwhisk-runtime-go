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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	}, "action_name": "long_running_step"}`

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
// in a real native OpenWhisk sequence), distinguished purely by the
// /run payload's own "action_name" field (docs/ACTION.md — a real
// per-activation field OpenWhisk always sends, unlike __OW_ACTION_NAME,
// which this process never sets for itself), resolving its OWN entry
// in the shared map — never a registry lookup (§7.1).
func TestRunHandler_EnergyMonitor_MixedSequence_OnlyNonInterruptibleStepEscapesEnforcement(t *testing.T) {
	sharedInterruptionClass := `{"step_kill_safe": "KILL_SAFE", "step_non_interruptible": "NON_INTERRUPTIBLE"}`

	t.Run("first step: KILL_SAFE remains enforced", func(t *testing.T) {
		t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
		t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
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
		}, "action_name": "step_kill_safe"}`

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
		// KILL_SAFE step above — only the request's own "action_name"
		// field differs, proving the runtime resolves ITS OWN entry
		// rather than e.g. always picking the first (or only) map entry.
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
		}, "action_name": "step_non_interruptible"}`

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

// 6. Regression test for the real production incident (not caught by
// tests 1/5 above, which always injected a bare __OW_ACTION_NAME
// matching the map exactly): isNonInterruptibleForThisStep() used to
// key its lookup on os.Getenv("__OW_ACTION_NAME") — a var this proxy
// process never sets for itself (only the CHILD action's own
// environment gets it, derived by the language layer from the /run
// payload, too late to matter here). On a real cluster this meant
// EVERY lookup missed, and the old "safe default is enforced" logic
// then froze/killed a NON_INTERRUPTIBLE step exactly as if no
// interruption_class had ever been declared for it.
//
// The fix moves resolution to the /run payload's own "action_name"
// field (docs/ACTION.md, always sent by OpenWhisk, namespace/package-
// qualified) and reverses the miss-default (CLAUDE.md §3.3 hardening):
// an unresolved name now means "do not enforce", not "enforce" — a
// trace that runs unmonitored already has a safe, tested catch-all
// (uncapped committed_j at settlement); a NON_INTERRUPTIBLE action
// frozen/killed by mistake has none.
//
// Both cases below are real, not hypothetical: a qualified action_name
// (what OpenWhisk actually sends) and a missing action_name (what this
// proxy's own environment always produced pre-fix, via
// __OW_ACTION_NAME). Both must leave the step unfrozen and unkilled;
// only the missing-name case should still be genuinely UNRESOLVED
// after the fix (the qualified name normalizes and resolves correctly)
// — so only that case must emit the new critical [safety] log.
func TestRunHandler_EnergyMonitor_ActionNameResolution_QualifiedOrMissing_NeverEnforcesNonInterruptible(t *testing.T) {
	cases := []struct {
		name            string
		actionNameField string // "" = field omitted from the request body entirely
		expectSafetyLog bool   // whether resolution should still fail even after the fix
	}{
		{
			name:            "qualified action_name resolves correctly via normalization",
			actionNameField: `, "action_name": "/guest/order/step_non_interruptible"`,
			expectSafetyLog: false,
		},
		{
			name:            "missing action_name stays unresolved, fails safe, logs critical",
			actionNameField: "",
			expectSafetyLog: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
			t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
			// Deliberately NOT setting __OW_ACTION_NAME anywhere in this
			// test — the whole point is that resolution must no longer
			// depend on it, in either direction.
			fs := newFakeSchedulerServer(t)

			var logBuf bytes.Buffer
			log.SetOutput(&logBuf)
			defer log.SetOutput(os.Stderr)

			os.RemoveAll("./action/energy_action_name_resolution")
			logf, err := ioutil.TempFile("/tmp", "log")
			require.NoError(t, err)
			ap := NewActionProxy("./action/energy_action_name_resolution", "", logf, logf)

			script := []byte(sleepThenRespondScriptContent("0.3"))
			_, err = ap.ExtractAction(&script, "bin")
			require.NoError(t, err)
			require.NoError(t, ap.StartLatestAction())
			defer ap.theExecutor.Stop()

			ts := httptest.NewServer(ap)
			defer ts.Close()

			requestBody := fmt.Sprintf(`{"value": {
				"energy_trace_id": "trace-action-name-res",
				"energy_reservation_id": "trace-action-name-res",
				"energy_execution_phase": "forward",
				"energy_execution_threshold_j": 1.0,
				"energy_consumed_before_j": 1.0,
				"energy_pause_enabled": true,
				"energy_pause_mode": "CGROUP_FREEZE",
				"energy_max_pause_duration_ms": 2000,
				"energy_max_pause_count": 1,
				"energy_interruption_class": {"step_non_interruptible": "NON_INTERRUPTIBLE"}
			}%s}`, tc.actionNameField)

			resp, status, err := doPost(ts.URL+"/run", requestBody)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status, "resp=%s", resp)

			var parsed map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
			assert.Equal(t, true, parsed["ok"], "the action must reach its own natural termination: %s", resp)

			time.Sleep(50 * time.Millisecond)
			assert.Empty(t, fs.getPausedEvents(), "must never be frozen regardless of resolution outcome (§3.3)")
			assert.Empty(t, fs.getKilledEvents(), "must never be killed regardless of resolution outcome (§3.3)")

			logged := logBuf.String()
			if tc.expectSafetyLog {
				require.Contains(t, logged, "[safety] ", "an unresolved name must emit a critical [safety] log")
				safetyLine := logged[strings.Index(logged, "[safety] ")+len("[safety] "):]
				safetyLine = strings.SplitN(strings.TrimSpace(safetyLine), "\n", 2)[0]
				var payload map[string]interface{}
				require.NoError(t, json.Unmarshal([]byte(safetyLine), &payload))
				assert.Equal(t, "INTERRUPTION_CLASS_UNRESOLVED", payload["event"])
				assert.Equal(t, "critical", payload["severity"])
			} else {
				assert.NotContains(t, logged, "INTERRUPTION_CLASS_UNRESOLVED",
					"a correctly-normalized qualified name must resolve without the safety log firing")
			}
		})
	}
}

// 7. Regression test for the real production incident found while
// demonstrating PLAYBOOK.md Phase 9's recovery-side pause/extend/resume
// round-trip (CLAUDE.md §3.2, §6.3): a compensation action (release_stock,
// cancel_fraud_hold, ...) never declares interruption_class by design —
// core/scheduler.py::_interruption_class_map() deliberately OMITS it from
// the map sent to the runtime. Before this fix, isNonInterruptibleForThisStep
// treated a resolved-but-map-absent action name identically to a genuine
// resolution failure (an empty ResolvedActionName) — silently disabling
// shouldMonitorEnergy() for EVERY compensation with a pause_policy. A
// compensation could overshoot its threshold by tens of joules with ample
// real time to spare and never freeze — confirmed live on a real cluster,
// not hypothetical. This test asserts the opposite of test 6 above: a
// resolved name absent from the map (the compensation shape) MUST still
// be frozen normally, and must NOT emit the critical [safety] log (this
// is the expected, accounted-for shape, not a failure).
func TestRunHandler_EnergyMonitor_CompensationActionAbsentFromMap_StillEnforcesPause(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	os.RemoveAll("./action/energy_compensation_absent_from_map")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_compensation_absent_from_map", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	// action_name resolves correctly ("release_stock", non-empty) but
	// energy_interruption_class carries an entry for a DIFFERENT action
	// only — release_stock itself is absent, exactly as
	// _interruption_class_map() sends it for a real compensation.
	requestBody := `{"value": {
		"energy_trace_id": "trace-compensation-map-absent",
		"energy_reservation_id": "trace-compensation-map-absent",
		"energy_execution_phase": "recovery",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"reserve_stock": "COMPENSATABLE"}
	}, "action_name": "/guest/order/release_stock"}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"])

	pausedEvents := fs.getPausedEvents()
	require.Len(t, pausedEvents, 1,
		"a compensation action legitimately absent from the interruption class map must still be frozen normally")
	ev := pausedEvents[0]
	assert.Equal(t, "recovery", ev.ExecutionPhase)

	logged := logBuf.String()
	assert.NotContains(t, logged, "INTERRUPTION_CLASS_UNRESOLVED",
		"a compensation action's own absence from the map is expected, not a resolution failure — no critical log")
}
