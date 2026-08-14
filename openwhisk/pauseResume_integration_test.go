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

// pauseResume_integration_test.go: the pause/extension/resume round trip
// against a REAL running scheduler/ process (core/scheduler.py's actual
// handle_execution_paused(), not fakeScheduler_test.go's Go stand-in) —
// PLAYBOOK.md Phase 7's required test list item 9 ("intégration
// scheduler<->runtime, mock ou réel selon ce que l'environnement de test
// permet").
//
// Skipped unless INTEGRATION_SCHEDULER_URL is set: this repo's default
// `go test` run has no Python process available, and silently faking
// this test would defeat its whole purpose. See
// scheduler/tests/integration_pause_server.py for the counterpart
// script that stands up the real server with a matching pre-admitted
// reservation — run together via
// scheduler/tests/run_go_python_integration.sh.

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

func TestPauseResume_Integration_RealPythonScheduler(t *testing.T) {
	schedulerURL := os.Getenv("INTEGRATION_SCHEDULER_URL")
	if schedulerURL == "" {
		t.Skip("INTEGRATION_SCHEDULER_URL not set — skipping the real cross-language " +
			"integration test (see scheduler/tests/run_go_python_integration.sh to run it for real)")
	}
	traceID := os.Getenv("INTEGRATION_TRACE_ID")
	if traceID == "" {
		traceID = "integ-trace-1"
	}
	t.Setenv("SCHEDULER_URL", schedulerURL)
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	os.RemoveAll("./action/pause_resume_integration")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/pause_resume_integration", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.3"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	// Threshold/consumed_before_j chosen to freeze on the very first
	// monitor tick (same determinism trick as pauseResume_test.go), and
	// LOW enough (relative to the 60J reservation
	// integration_pause_server.py admits for this trace_id) that the
	// real scheduler's extend_forward_reservation() has room to grant a
	// full extension — mirroring CLAUDE.md §5.1's own reference numbers.
	resp, status, err := doPost(ts.URL+"/run", pausedRequestBody(traceID, 55.0))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	assert.Equal(t, true, parsed["ok"], "the real scheduler must have granted RESUME_EXECUTION for the process to have completed")
}
