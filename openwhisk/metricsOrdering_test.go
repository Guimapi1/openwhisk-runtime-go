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

// metricsOrdering_test.go: CLAUDE.md §6.9 hardening pass, point 2. Before
// this fix, runHandler.go's killInfo branch called
// ap.recordMetrics("/run", ...) (fire-and-forget push to the collector,
// via `go pushMetrics(...)` inside metrics_helpers.go) AFTER already
// having launched `go postExecutionKilled(event)` — two independent
// goroutines racing with no synchronization between them. The scheduler's
// handle_execution_killed() queries collector.get_energy_for_trace(trace_id)
// the MOMENT it receives EXECUTION_KILLED, so nothing guaranteed this
// activation's own measurement had actually landed at the collector by
// then.
//
// The fix: ap.recordMetricsSync(...) (metrics_helpers.go) pushes
// SYNCHRONOUSLY (a direct, blocking pushMetrics() call, not `go
// pushMetrics(...)`), and is called BEFORE `go postExecutionKilled(event)`
// in runHandler.go. This test locks in that ordering as a real
// happens-before guarantee (Go's own program order: pushMetrics's HTTP
// round-trip fully completes, response received, before the `go`
// statement launching postExecutionKilled is even reached) — not a timing
// coincidence that could flake, and not something a future refactor
// should be able to silently regress.

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeCollectorServer stands in for the collector's own /collect
// endpoint (pushMetrics's target, pushgateway.go) — records receipt via
// an atomic flag the test can check WITHOUT polling, since the flag is
// set (by the collector's own handler, synchronously) before pushMetrics's
// http.Client.Do() call returns to its caller.
func newFakeCollectorServer(t *testing.T, received *int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// newSlowFakeCollectorServer is newFakeCollectorServer's sibling for the
// NORMAL-completion ordering test below: it sleeps `delay` before
// responding, and only sets the flag AFTER that sleep — used to prove
// the /run response genuinely waited for the push to finish, not merely
// that the flag eventually got set at some point after the response
// (which an async `go pushMetrics(...)` would also achieve, just without
// the wait).
func newSlowFakeCollectorServer(t *testing.T, delay time.Duration, received *int32) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		atomic.StoreInt32(received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// 9. recordMetricsSync's push to the collector has ALREADY completed by
// the time EXECUTION_KILLED reaches the scheduler — verified via a
// fake collector server (records receipt through an atomic flag) and the
// existing fake scheduler server (records the EXECUTION_KILLED event) —
// the flag must be set the instant the kill event arrives, every single
// run, not merely "usually" (a flaky, timing-based race would show up as
// occasional failures across repeated runs; a real happens-before
// guarantee never does).
func TestRunHandler_RecordMetricsSyncCompletesBeforeExecutionKilledIsSent(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	var collectorReceived int32
	collector := newFakeCollectorServer(t, &collectorReceived)
	t.Setenv("COLLECTOR_URL", collector.URL)

	fs := newFakeSchedulerServer(t)

	os.RemoveAll("./action/energy_metrics_ordering")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_metrics_ordering", "", logf, logf)

	// Never responds on its own: only the energy-threshold kill ends
	// this request.
	script := []byte("#!/bin/sh\nwhile read a; do :; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"quantity": 1,
		"energy_trace_id": "trace-metrics-order",
		"energy_reservation_id": "trace-metrics-order",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`

	_, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	waitFor(t, 2*time.Second, "EXECUTION_KILLED delivered to the scheduler channel", func() bool {
		return len(fs.getKilledEvents()) == 1
	})

	// By construction (recordMetricsSync is called, and fully returns,
	// BEFORE `go postExecutionKilled(event)` even runs — runHandler.go),
	// the collector must have already recorded receipt the moment
	// EXECUTION_KILLED arrives. No sleep, no retry: checking it exactly
	// once, right here, is the point of the test.
	assert.Equal(t, int32(1), atomic.LoadInt32(&collectorReceived),
		"the collector must have already received this activation's own "+
			"metrics push by the time EXECUTION_KILLED reaches the scheduler")
}

// Required test #2 (point 3 of the hardening pass): the same guarantee,
// applied to the NORMAL completion path — a test that would FAIL without
// recordMetricsSync there. The fake collector deliberately sleeps before
// responding; if runHandler.go still used the old async recordMetrics()
// (fire-and-forget `go pushMetrics(...)`), the /run response would
// return almost immediately, well before that sleep elapses, and the
// "received" flag would very likely still be false the instant doPost()
// returns. With recordMetricsSync called before w.Write(), the response
// cannot come back before the collector's sleep-then-respond completes.
func TestRunHandler_RecordMetricsSyncCompletesBeforeNormalResponseIsSent(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))

	const collectorDelay = 150 * time.Millisecond
	var collectorReceived int32
	collector := newSlowFakeCollectorServer(t, collectorDelay, &collectorReceived)
	t.Setenv("COLLECTOR_URL", collector.URL)

	os.RemoveAll("./action/energy_metrics_ordering_normal")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_metrics_ordering_normal", "", logf, logf)

	// Responds immediately on its own — this is the NORMAL completion
	// path, no energy threshold involved at all.
	script := []byte("#!/bin/sh\nwhile read a; do echo '{\"ok\": true}' >&3; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestStart := time.Now()
	resp, status, err := doPost(ts.URL+"/run", `{"value": {"quantity": 1}}`)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)
	elapsed := time.Since(requestStart)

	// testify v1.3.0 (pinned by this repo) has no GreaterOrEqual, hence
	// the explicit comparison (same pattern as this repo's other tests).
	assert.Truef(t, elapsed >= collectorDelay,
		"the /run response returned after only %s, before the collector's own "+
			"%s response delay had even elapsed — recordMetricsSync is not "+
			"actually blocking the response", elapsed, collectorDelay)
	assert.Equal(t, int32(1), atomic.LoadInt32(&collectorReceived),
		"the collector must have already received this activation's own "+
			"metrics push by the time the /run response comes back")
}

// TestRunHandler_RecordMetricsSyncCompletesBeforeExecutionKilledIsSent_RealCollector
// is the SAME ordering scenario as the local test above, but pointed at
// the REAL cluster's live collector service (real network latency, not
// an in-process httptest.Server) — the specific confirmation requested
// for point 2 of the hardening pass. Skipped unless
// INTEGRATION_COLLECTOR_URL is set (this repo's default `go test` run
// has no cluster/VPN access), mirroring
// pauseResume_integration_test.go's own INTEGRATION_SCHEDULER_URL
// convention.
//
// What this test can and cannot prove: the ordering guarantee itself
// (recordMetricsSync fully returns, on the SAME goroutine, before the
// `go postExecutionKilled(event)` statement is even reached) is Go's own
// program-order semantics — deterministic, and NOT something real
// network latency could break, only slow down. What real latency COULD
// break is something this local-httptest test can't see: DNS/TLS
// oddities, an unexpected response shape from the real collector,
// firewall/timeout surprises — this test exercises the REAL round trip
// end to end (real DNS, real TLS-less HTTP, real ~tens-of-ms network
// latency to Grid'5000) to rule those out, and captures pushMetrics's
// own success log line as independent confirmation the push genuinely
// completed (not merely "didn't crash").
func TestRunHandler_RecordMetricsSyncCompletesBeforeExecutionKilledIsSent_RealCollector(t *testing.T) {
	collectorURL := os.Getenv("INTEGRATION_COLLECTOR_URL")
	if collectorURL == "" {
		t.Skip("INTEGRATION_COLLECTOR_URL not set — skipping the real-cluster " +
			"collector confirmation (set it to the live collector's base URL, " +
			"e.g. http://paradoxe-31.rennes.grid5000.fr:30090, VPN/cluster access required)")
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")
	t.Setenv("COLLECTOR_URL", collectorURL)

	fs := newFakeSchedulerServer(t)

	os.RemoveAll("./action/energy_metrics_ordering_real")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_metrics_ordering_real", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do :; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	requestBody := `{"value": {
		"quantity": 1,
		"energy_trace_id": "trace-metrics-order-real",
		"energy_reservation_id": "trace-metrics-order-real",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 1.0,
		"energy_consumed_before_j": 1.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`

	requestStart := time.Now()
	_, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	waitFor(t, 10*time.Second, "EXECUTION_KILLED delivered to the scheduler channel", func() bool {
		return len(fs.getKilledEvents()) == 1
	})
	elapsed := time.Since(requestStart)

	logged := logBuf.String()
	assert.True(t, strings.Contains(logged, "pushMetrics: sent /run"),
		"pushMetrics must have logged genuine success against the real collector "+
			"(not merely avoided crashing) before EXECUTION_KILLED fired; full log:\n%s", logged)

	t.Logf("real-cluster recordMetricsSync + EXECUTION_KILLED round trip took %s "+
		"(collector=%s) — this is the real added latency on the kill path from this "+
		"vantage point; from INSIDE the cluster it would be substantially lower "+
		"(no cross-site routing)", elapsed, collectorURL)
}
