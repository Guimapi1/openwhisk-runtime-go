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

// nonInterruptible_test.go: PLAYBOOK.md Phase 10 → 16, CLAUDE.md §0
// decision 18, §3.3. NON_INTERRUPTIBLE became UNKILLABLE: it is now
// FROZEN and EXTENDED at its threshold exactly like any other class
// (shouldMonitorEnergy no longer skips it) — what stays absolutely
// forbidden is a KILL. runPauseCycle() refuses every path that would
// otherwise kill an UNKILLABLE step (an explicit KILL_EXECUTION command
// included — defense in depth), staying frozen and re-polling until it
// gets a genuine RESUME_EXECUTION.
//
// Fixtures set energy_consumed_before_j already at/above
// energy_execution_threshold_j (determinism trick, see executor_test.go)
// so the very first monitor tick reaches the threshold — making "was
// frozen" / "was never killed" meaningful, non-vacuous assertions.

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

// 1. PLAYBOOK Phase 16 (rewrites _NeverFreezesOrKills): an UNKILLABLE
// action that reaches its threshold IS frozen — an EXECUTION_PAUSED goes
// out — the scheduler grants RESUME_EXECUTION, and it runs to natural
// termination. It is NEVER killed.
func TestRunHandler_EnergyMonitor_Unkillable_FrozenThenResumed_NeverKilled(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)
	// Default commandFunc already grants RESUME with a huge threshold —
	// exactly what a normal, successful extension looks like.

	os.RemoveAll("./action/energy_unkillable")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_unkillable", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"energy_trace_id": "trace-unkillable",
		"energy_reservation_id": "trace-unkillable",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"long_running_step": "UNKILLABLE"}
	}, "action_name": "long_running_step"}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"], "the action must reach its own natural termination: %s", resp)

	time.Sleep(50 * time.Millisecond)
	assert.NotEmpty(t, fs.getPausedEvents(), "an UNKILLABLE step IS frozen at its threshold now (Phase 16)")
	assert.Empty(t, fs.getKilledEvents(), "an UNKILLABLE step must never be killed (§3.3)")

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

// 5. In a two-step sequence (KILL_SAFE then UNKILLABLE, sharing one
// per-component interruption_class map), each step resolves its OWN
// entry from the /run payload's "action_name" field. PLAYBOOK Phase 16:
// the KILL_SAFE step is still killed on overrun; the UNKILLABLE step is
// FROZEN and RESUMED (never killed).
func TestRunHandler_EnergyMonitor_MixedSequence_KillSafeKilled_UnkillableFrozenNotKilled(t *testing.T) {
	sharedInterruptionClass := `{"step_kill_safe": "KILL_SAFE", "step_unkillable": "UNKILLABLE"}`

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

	t.Run("second step: UNKILLABLE is frozen and resumed, never killed", func(t *testing.T) {
		t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
		t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
		fs := newFakeSchedulerServer(t) // default commandFunc grants RESUME

		os.RemoveAll("./action/energy_mixed_seq_unkillable")
		logf, err := ioutil.TempFile("/tmp", "log")
		require.NoError(t, err)
		ap := NewActionProxy("./action/energy_mixed_seq_unkillable", "", logf, logf)

		script := []byte(sleepThenRespondScriptContent("0.3"))
		_, err = ap.ExtractAction(&script, "bin")
		require.NoError(t, err)
		require.NoError(t, ap.StartLatestAction())
		defer ap.theExecutor.Stop()

		ts := httptest.NewServer(ap)
		defer ts.Close()

		// Same shared map, same threshold/consumed_before shape — only
		// the request's own "action_name" differs, proving the runtime
		// resolves ITS OWN entry. pause_enabled=true (UNKILLABLE's
		// pause_policy is mandatory now, §3.4).
		requestBody := `{"value": {
			"__energy_state": {
				"trace_id": "trace-mixed-seq",
				"reservation_id": "trace-mixed-seq",
				"execution_phase": "forward",
				"execution_threshold_j": 1.0,
				"consumed_before_j": 1.0,
				"pause_enabled": true,
				"pause_mode": "CGROUP_FREEZE",
				"max_pause_duration_ms": 2000,
				"max_pause_count": 1,
				"interruption_class": ` + sharedInterruptionClass + `
			}
		}, "action_name": "step_unkillable"}`

		resp, status, err := doPost(ts.URL+"/run", requestBody)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, "resp=%s", resp)

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
		assert.Equal(t, true, parsed["ok"])

		time.Sleep(50 * time.Millisecond)
		assert.Empty(t, fs.getKilledEvents(), "the UNKILLABLE step must never be killed")
		assert.NotEmpty(t, fs.getPausedEvents(), "the UNKILLABLE step IS frozen at its threshold now")
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
// PLAYBOOK Phase 16 update: a CORRECTLY resolved UNKILLABLE name is now
// FROZEN (monitored like any class) — only the genuinely UNRESOLVED case
// still skips enforcement (fail-safe) and emits the critical [safety]
// log. Neither case is ever KILLED.
func TestRunHandler_EnergyMonitor_ActionNameResolution_QualifiedResolvesAndFreezes_MissingFailsSafe(t *testing.T) {
	cases := []struct {
		name            string
		actionNameField string // "" = field omitted from the request body entirely
		expectSafetyLog bool   // resolution genuinely failed (unresolved) -> fail-safe, log
		expectFrozen    bool   // resolved UNKILLABLE -> monitored -> frozen at threshold
	}{
		{
			name:            "qualified action_name resolves -> UNKILLABLE step is frozen",
			actionNameField: `, "action_name": "/guest/order/step_unkillable"`,
			expectSafetyLog: false,
			expectFrozen:    true,
		},
		{
			name:            "missing action_name stays unresolved -> fails safe, logs critical, not frozen",
			actionNameField: "",
			expectSafetyLog: true,
			expectFrozen:    false,
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
				"energy_interruption_class": {"step_unkillable": "UNKILLABLE"}
			}%s}`, tc.actionNameField)

			resp, status, err := doPost(ts.URL+"/run", requestBody)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status, "resp=%s", resp)

			var parsed map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
			assert.Equal(t, true, parsed["ok"], "the action must reach its own natural termination: %s", resp)

			time.Sleep(50 * time.Millisecond)
			if tc.expectFrozen {
				assert.NotEmpty(t, fs.getPausedEvents(), "a resolved UNKILLABLE step is frozen at threshold (Phase 16)")
			} else {
				assert.Empty(t, fs.getPausedEvents(), "an unresolved class fails safe: no enforcement, no freeze")
			}
			assert.Empty(t, fs.getKilledEvents(), "never killed regardless of resolution outcome (§3.3)")

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

// 8. PLAYBOOK Phase 16 objective 3 / required test #4 — DEFENSE IN
// DEPTH. The scheduler must NEVER send KILL_EXECUTION for an UNKILLABLE
// step; if one arrives anyway (simulated here), the runtime REFUSES it:
// a critical [safety] incident (KILL_EXECUTION_REFUSED_UNKILLABLE), the
// process is NOT killed, it stays frozen and re-polls. The scheduler
// then answers RESUME on the re-poll so the action completes.
func TestRunHandler_EnergyMonitor_Unkillable_RefusesKillExecutionCommand(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	t.Setenv("UNKILLABLE_REPOLL_INTERVAL_MS", "20") // fast re-poll for the test

	fs := newFakeSchedulerServer(t)
	var calls int
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		calls++
		if calls == 1 {
			// The command that must be refused.
			return SchedulerCommand{
				Command: "KILL_EXECUTION", TraceID: ev.TraceID,
				ReservationID: ev.ReservationID, PauseID: ev.PauseID,
				Reason: "SHOULD_NEVER_HAPPEN_FOR_UNKILLABLE",
			}
		}
		// The re-poll gets a genuine resume, so the action can finish.
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: 1e9,
		}
	})

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	os.RemoveAll("./action/energy_unkillable_refuse_kill")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_unkillable_refuse_kill", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.4"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"energy_trace_id": "trace-unkillable-refuse-kill",
		"energy_reservation_id": "trace-unkillable-refuse-kill",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"long_running_step": "UNKILLABLE"}
	}, "action_name": "long_running_step"}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"], "the action must NOT be killed — it completes: %s", resp)

	time.Sleep(50 * time.Millisecond)
	assert.Empty(t, fs.getKilledEvents(),
		"KILL_EXECUTION for an UNKILLABLE step must be refused — no EXECUTION_KILLED ever sent")
	assert.True(t, len(fs.getPausedEvents()) >= 2,
		"the runtime must re-poll after refusing the kill (initial pause + at least one re-poll)")

	logged := logBuf.String()
	require.Contains(t, logged, "[safety] ", "the refusal must be a [safety] incident")
	// Find the [safety] line that carries the refusal event and decode it.
	var refusal map[string]interface{}
	for _, line := range strings.Split(logged, "\n") {
		i := strings.Index(line, "[safety] ")
		if i < 0 || !strings.Contains(line, "KILL_EXECUTION_REFUSED_UNKILLABLE") {
			continue
		}
		require.NoError(t, json.Unmarshal([]byte(line[i+len("[safety] "):]), &refusal))
		break
	}
	require.NotNil(t, refusal, "a KILL_EXECUTION_REFUSED_UNKILLABLE [safety] line must be present")
	assert.Equal(t, "KILL_EXECUTION_REFUSED_UNKILLABLE", refusal["event"])
	assert.Equal(t, "critical", refusal["severity"])
	assert.Equal(t, "trace-unkillable-refuse-kill", refusal["trace_id"])
}
