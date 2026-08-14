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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var m = map[string]string{}

func ExampleNewExecutor_failed() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "true", m)
	err := proc.Start(false)
	fmt.Println(err)
	proc.Stop()
	proc = NewExecutor(log, log, "/bin/pwd", m)
	err = proc.Start(false)
	fmt.Println(err)
	proc.Stop()
	proc = NewExecutor(log, log, "donotexist", m)
	err = proc.Start(false)
	fmt.Println(err)
	proc.Stop()
	proc = NewExecutor(log, log, "/etc/passwd", m)
	err = proc.Start(false)
	fmt.Println(err)
	proc.Stop()
	// Output:
	// command exited
	// command exited
	// command exited
	// command exited
}

func ExampleNewExecutor_bc() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/bc.sh", m)
	err := proc.Start(false)
	fmt.Println(err)
	res, _, _ := proc.Interact([]byte("2+2"), nil)
	fmt.Printf("%s", res)
	proc.Stop()
	dump(log)
	// Output:
	// <nil>
	// 4
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
}

func ExampleNewExecutor_hello() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/hello.sh", m)
	err := proc.Start(false)
	fmt.Println(err)
	res, _, _ := proc.Interact([]byte(`{"value":{"name":"Mike"}}`), nil)
	fmt.Printf("%s", res)
	proc.Stop()
	dump(log)
	// Output:
	// <nil>
	// {"hello": "Mike"}
	// msg=hello Mike
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
}

func ExampleNewExecutor_env() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/env.sh", map[string]string{"TEST_HELLO": "WORLD", "TEST_HI": "ALL"})
	err := proc.Start(false)
	fmt.Println(err)
	res, _, _ := proc.Interact([]byte(`{"value":{"name":"Mike"}}`), nil)
	fmt.Printf("%s", res)
	proc.Stop()
	dump(log)
	// Output:
	// <nil>
	// { "env": "TEST_HELLO=WORLD TEST_HI=ALL"}
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
}

func ExampleNewExecutor_ack() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/hi", m)
	err := proc.Start(true)
	fmt.Println(err)
	proc.Stop()
	dump(log)
	// Output:
	// Command exited abruptly during initialization.
	// hi
}

func ExampleNewExecutor_badack() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/badack.sh", m)
	err := proc.Start(true)
	fmt.Println(err)
	proc.Stop()
	dump(log)
	// Output:
	// invalid character 'b' looking for beginning of value
}

func ExampleNewExecutor_badack2() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/badack2.sh", m)
	err := proc.Start(true)
	fmt.Println(err)
	proc.Stop()
	dump(log)
	// Output:
	// The action did not initialize properly.
}

func ExampleNewExecutor_helloack() {
	log, _ := ioutil.TempFile("", "log")
	proc := NewExecutor(log, log, "_test/helloack/exec", m)
	err := proc.Start(true)
	fmt.Println(err)
	res, _, _ := proc.Interact([]byte(`{"value":{"name":"Mike"}}`), nil)
	fmt.Printf("%s", res)
	proc.Stop()
	dump(log)
	// Output:
	// <nil>
	// {"hello": "Mike"}
	// msg=hello Mike
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
	// XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX
}

// ---------------------------------------------------------------------
// Energy threshold detection + local synchronous kill (CLAUDE.md §3.1,
// §7.1, §7.2, §7.5's sidecar-sourcing rule; PLAYBOOK Phase 5).
//
// RAPL_PATH is pointed at a fake, test-owned file throughout: readEnergy()
// only needs a parseable integer, real Intel RAPL hardware is not
// required, and this keeps the tests deterministic across environments.
// A kill is made deterministic (independent of whether this sandbox can
// actually attribute nonzero CPU-weighted energy to the monitored pid)
// by setting energy_consumed_before_j already at/above
// energy_execution_threshold_j: the very first monitor tick then
// satisfies consumed_before_j + step >= threshold regardless of what
// `step` itself measures.
// ---------------------------------------------------------------------

func newFakeRAPLFile(t *testing.T) string {
	t.Helper()
	f, err := ioutil.TempFile("", "fake_rapl_*.txt")
	require.NoError(t, err)
	_, err = f.WriteString("1000000")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func writeTempScript(t *testing.T, content string) string {
	t.Helper()
	f, err := ioutil.TempFile("", "energy_test_*.sh")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chmod(f.Name(), 0755))
	return f.Name()
}

// processAlive reports whether pid is still running, via the classic
// Unix "signal 0" probe (sends no actual signal, just checks existence).
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// 1. Stays under threshold: completes normally, __energy_state is
// reinjected with consumed_before_j up to date (via the phase 3 sidecar).
func TestRunHandler_EnergyMonitor_StaysUnderThreshold_ReinjectsEnergyState(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	os.RemoveAll("./action/energy_kill_under")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_kill_under", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"quantity": 1,
		"energy_trace_id": "trace-under",
		"energy_reservation_id": "trace-under",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 100000.0,
		"energy_consumed_before_j": 0.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": "KILL_SAFE"
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))

	_, wasKilled := parsed["event"]
	assert.False(t, wasKilled, "action should have completed normally: %s", resp)

	stateRaw, ok := parsed[energyStateKey]
	require.True(t, ok, "%s must be present in the response: %s", energyStateKey, resp)
	stateMap, ok := stateRaw.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "trace-under", stateMap["trace_id"])
	consumedBefore, ok := stateMap["consumed_before_j"].(float64)
	require.True(t, ok)
	assert.True(t, consumedBefore >= 0.0)
}

// 2. Exceeds threshold with pauseEnabled=false: killed before its
// natural end. EXECUTION_KILLED is no longer embedded in the /run
// response (PLAYBOOK.md Phase 7's resolved open question #2) — it's
// POSTed to the dedicated scheduler channel, fire-and-forget, while /run
// itself returns a neutral failure marker.
func TestRunHandler_EnergyMonitor_ExceedsThreshold_EmitsExecutionKilled(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	fs := newFakeSchedulerServer(t)

	os.RemoveAll("./action/energy_kill_exceed")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_kill_exceed", "", logf, logf)

	// Never responds on its own: if the monitor failed to kill it, the
	// request would hang instead of failing fast.
	script := []byte("#!/bin/sh\nwhile read a; do :; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"quantity": 1,
		"energy_trace_id": "trace-over",
		"energy_reservation_id": "trace-over",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": "KILL_SAFE"
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	assert.NotContains(t, resp, "quantity") // original arguments never in the /run response

	waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered to the scheduler channel", func() bool {
		return len(fs.getKilledEvents()) == 1
	})
	event := fs.getKilledEvents()[0]

	assert.Equal(t, "EXECUTION_KILLED", event.Event)
	assert.Equal(t, "trace-over", event.TraceID)
	assert.Equal(t, "trace-over", event.ReservationID)
	assert.Equal(t, "", event.PauseID) // no pause cycle happened, pauseEnabled=false
	assert.Equal(t, "forward", event.ExecutionPhase)
	assert.True(t, event.EnergyBudgetExceeded)
	assert.True(t, event.EnergyConsumedJ >= 1.0)
	assert.Equal(t, map[string]interface{}{"quantity": float64(1)}, event.EnergyOriginalArguments)
}

// 3. Disabled/negative threshold: no kill, monitoring without
// enforcement (§7.2) — current behaviour unchanged.
func TestRunHandler_EnergyMonitor_DisabledThreshold_NeverKills(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	os.RemoveAll("./action/energy_kill_disabled")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_kill_disabled", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"ok\\\": true}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	// consumed_before_j is already huge, but threshold<=0 must still
	// disable enforcement entirely (§7.2).
	requestBody := `{"value": {
		"energy_trace_id": "trace-disabled",
		"energy_reservation_id": "trace-disabled",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 0.0,
		"energy_consumed_before_j": 999999.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": "KILL_SAFE"
	}}`

	resp, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	_, wasKilled := parsed["event"]
	assert.False(t, wasKilled, "a disabled threshold must never kill: %s", resp)
}

// 4. The kill covers child processes, not just the main PID.
func TestExecutor_Interact_EnergyKillCoversChildProcesses(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))

	childPidFile, err := ioutil.TempFile("", "child_pid_*.txt")
	require.NoError(t, err)
	require.NoError(t, childPidFile.Close())
	defer os.Remove(childPidFile.Name())

	scriptPath := writeTempScript(t, "#!/bin/sh\n"+
		"sleep 30 &\n"+
		"echo $! > \"$1\"\n"+
		"while read a; do :; done\n")
	defer os.Remove(scriptPath)

	logf, err := ioutil.TempFile("", "log")
	require.NoError(t, err)
	proc := NewExecutor(logf, logf, scriptPath, m, childPidFile.Name())
	require.NoError(t, proc.Start(false))

	// Wait for the script to have spawned its child and reported its PID.
	var childPid int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := ioutil.ReadFile(childPidFile.Name())
		if readErr == nil && len(data) > 0 {
			if _, scanErr := fmt.Sscanf(string(data), "%d", &childPid); scanErr == nil && childPid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, childPid > 0, "child process never reported its PID")
	require.True(t, processAlive(childPid), "child process should be alive before the kill")

	energy := &EnergyState{
		TraceID:             "trace-children",
		ReservationID:       "trace-children",
		ExecutionPhase:      "forward",
		ExecutionThresholdJ: 1.0,
		ConsumedBeforeJ:     1.0,
		PauseEnabled:        false,
	}
	_, _, killInfo := proc.Interact([]byte("x"), energy)
	require.NotNil(t, killInfo, "the main process should have been killed")

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(childPid) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.False(t, processAlive(childPid), "child process must be killed along with the main process")
}

// 5. The threshold is read correctly whether the request is a first step
// (energy_* directly in the body) or a subsequent step (nested in
// __energy_state) — reusing phase 3's sidecar fixtures/shapes.
func TestRunHandler_EnergyMonitor_ThresholdReadFromBothSidecarSources(t *testing.T) {
	cases := []struct {
		name            string
		body            string
		expectedTraceID string
	}{
		{
			name: "first step: energy_* directly in body",
			body: `{"value": {
				"energy_trace_id": "trace-first",
				"energy_reservation_id": "trace-first",
				"energy_execution_phase": "forward",
				"energy_execution_threshold_j": 1.0,
				"energy_consumed_before_j": 1.0,
				"energy_pause_enabled": false,
				"energy_pause_mode": "",
				"energy_max_pause_duration_ms": 0,
				"energy_max_pause_count": 0,
				"energy_interruption_class": "KILL_SAFE"
			}}`,
			expectedTraceID: "trace-first",
		},
		{
			name: "subsequent step: fields nested in __energy_state",
			body: `{"value": {
				"__energy_state": {
					"trace_id": "trace-next",
					"reservation_id": "trace-next",
					"execution_phase": "forward",
					"execution_threshold_j": 1.0,
					"consumed_before_j": 1.0,
					"pause_enabled": false,
					"pause_mode": "",
					"max_pause_duration_ms": 0,
					"max_pause_count": 0,
					"interruption_class": "KILL_SAFE"
				}
			}}`,
			expectedTraceID: "trace-next",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
			t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
			fs := newFakeSchedulerServer(t)

			dir := fmt.Sprintf("./action/energy_kill_source_%d", i)
			os.RemoveAll(dir)
			logf, err := ioutil.TempFile("/tmp", "log")
			require.NoError(t, err)
			ap := NewActionProxy(dir, "", logf, logf)

			script := []byte("#!/bin/sh\nwhile read a; do :; done\n")
			_, err = ap.ExtractAction(&script, "bin")
			require.NoError(t, err)
			require.NoError(t, ap.StartLatestAction())

			ts := httptest.NewServer(ap)
			defer ts.Close()

			_, status, err := doPost(ts.URL+"/run", tc.body)
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, status)

			waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered to the scheduler channel", func() bool {
				return len(fs.getKilledEvents()) == 1
			})
			event := fs.getKilledEvents()[0]
			assert.Equal(t, "EXECUTION_KILLED", event.Event)
			assert.Equal(t, tc.expectedTraceID, event.TraceID)
			assert.True(t, event.EnergyBudgetExceeded)
		})
	}
}
