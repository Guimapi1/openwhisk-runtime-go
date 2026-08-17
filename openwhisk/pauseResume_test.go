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

// pauseResume_test.go: the forward-phase pause/extension/resume
// round-trip through the REAL HTTP stack (runHandler.go -> Executor ->
// energyMonitor.go -> schedulerChannel.go -> fakeSchedulerServer),
// CLAUDE.md §5's runtime steps 4-7, §7.5, §7.6; PLAYBOOK.md Phase 7's
// required test list items 3, 6, 7, 9.
//
// Determinism trick shared with executor_test.go's phase-5 tests: a
// fixed fake RAPL reading makes attributedEnergyUJ's step delta ~0, so
// setting energy_consumed_before_j already at/above
// energy_execution_threshold_j makes the monitor's very first tick
// freeze deterministically, regardless of what it actually measures.

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

func pausedRequestBody(traceID string, thresholdJ float64) string {
	return `{"value": {
		"energy_trace_id": "` + traceID + `",
		"energy_reservation_id": "` + traceID + `",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": ` + jsonFloat(thresholdJ) + `,
		"energy_consumed_before_j": ` + jsonFloat(thresholdJ) + `,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}}`
}

func jsonFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// 1. Full round trip: freeze -> EXECUTION_PAUSED -> scheduler grants
// RESUME_EXECUTION -> the process genuinely resumes and completes
// normally (CLAUDE.md §5.1's spirit, at the runtime-orchestration
// level — the exact 60J/56.2J/80J arithmetic is a Python-side concern,
// already covered precisely by
// scheduler/tests/test_reservation.py::test_section_5_1_numeric_example_full_extension_and_resume).
func TestPauseResume_FullRoundTrip_ResumesAndCompletes(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: 1e9, // effectively "never freeze again"
		}
	})

	os.RemoveAll("./action/pause_resume_full")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_resume_full", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	resp, status, err := doPost(ts.URL+"/run", pausedRequestBody("trace-resume", 1.0))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"])

	pausedEvents := fs.getPausedEvents()
	require.Len(t, pausedEvents, 1, "exactly one freeze cycle expected")
	ev := pausedEvents[0]
	assert.Equal(t, "EXECUTION_PAUSED", ev.Event)
	assert.Equal(t, "trace-resume", ev.TraceID)
	assert.Equal(t, "trace-resume", ev.ReservationID)
	assert.Equal(t, "forward", ev.ExecutionPhase)
	assert.NotEmpty(t, ev.PauseID)
	assert.True(t, ev.PauseEffectiveAt >= ev.PauseRequestedAt)

	assert.Empty(t, fs.getKilledEvents(), "a granted resume must never also emit EXECUTION_KILLED")
}

// 2. Full round trip, kill branch: the scheduler answers EXECUTION_PAUSED
// with KILL_EXECUTION (CLAUDE.md §6.7's KILL_SAFE fallback) — the
// process is killed via the SAME cgroup path as the pauseEnabled=false
// case, EXECUTION_KILLED is emitted with a NON-empty pause_id (unlike
// the direct-kill case), and /run returns the neutral failure marker.
func TestPauseResume_SchedulerRespondsKill_ProcessKilledAndEventEmitted(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		return SchedulerCommand{
			Command: "KILL_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			Reason: "EXTENSION_TIMEOUT",
		}
	})

	os.RemoveAll("./action/pause_resume_kill")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_resume_kill", "", logf, logf)

	// Never responds: would only matter if the process were (wrongly)
	// resumed instead of killed.
	script := []byte("#!/bin/sh\nwhile read a; do sleep 30; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	_, status, err := doPost(ts.URL+"/run", pausedRequestBody("trace-pausekill", 1.0))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered", func() bool {
		return len(fs.getKilledEvents()) == 1
	})
	killed := fs.getKilledEvents()[0]
	assert.Equal(t, "trace-pausekill", killed.TraceID)
	assert.NotEmpty(t, killed.PauseID, "a kill following a pause cycle must report that pause_id")

	paused := fs.getPausedEvents()
	require.Len(t, paused, 1)
	assert.Equal(t, killed.PauseID, paused[0].PauseID)
}

// 3. A RESUME_EXECUTION command whose pause_id does not match the
// active pause cycle (stale/mismatched — CLAUDE.md §6.6: "une commande
// avec un pause_id obsolète est ignorée et loggée") must not crash the
// runtime or be silently honoured; the safe response is to kill rather
// than resume without a valid authorization for THIS pause_id
// (CLAUDE.md §4.3).
func TestPauseResume_MismatchedPauseIDInCommand_KillsRatherThanResumes(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: "some-other-stale-pause-id",
			NewExecutionThresholdJ: 1e9,
		}
	})

	os.RemoveAll("./action/pause_resume_mismatch")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_resume_mismatch", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do sleep 30; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	_, status, err := doPost(ts.URL+"/run", pausedRequestBody("trace-mismatch", 1.0))
	require.NoError(t, err, "the handler must respond, not hang or crash, on a mismatched pause_id")
	require.Equal(t, http.StatusBadRequest, status)

	waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered despite the mismatched command", func() bool {
		return len(fs.getKilledEvents()) == 1
	})
	assert.Equal(t, "trace-mismatch", fs.getKilledEvents()[0].TraceID)
}

// 4. A freeze on a request whose energy state arrives via __energy_state
// (the "later step of a sequence" sidecar path, phase 3) is handled
// identically to one whose energy state arrives directly as energy_*
// params (the first-step path) — the pause/resume mechanism does not
// care which step it's on, mirroring
// scheduler/tests/test_scheduler.py::test_handle_execution_paused_second_step_of_sequence_same_trace_id
// on the Python side.
func TestPauseResume_FreezeOnLaterSequenceStep_ViaEnergyStateSidecar(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: 1e9,
		}
	})

	os.RemoveAll("./action/pause_resume_later_step")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_resume_later_step", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"__energy_state": {
			"trace_id": "trace-second-step",
			"reservation_id": "trace-second-step",
			"execution_phase": "forward",
			"execution_threshold_j": 1.0,
			"consumed_before_j": 1.0,
			"pause_enabled": true,
			"pause_mode": "CGROUP_FREEZE",
			"max_pause_duration_ms": 2000,
			"max_pause_count": 1,
			"interruption_class": {"action": "KILL_SAFE"}
		}
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"])

	paused := fs.getPausedEvents()
	require.Len(t, paused, 1)
	assert.Equal(t, "trace-second-step", paused[0].TraceID)
	assert.Equal(t, "trace-second-step", paused[0].ReservationID)
}

func sleepThenRespondScriptContent(sleepSeconds string) string {
	return "#!/bin/sh\nwhile read a; do sleep " + sleepSeconds + "; echo '{\"ok\": true}' >&3; done\n"
}
