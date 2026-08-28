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

// energyAttributionAfterKill_test.go: regression test for a real
// incident found on cluster (see CLAUDE.md, EXECUTION_KILLED_
// MEASUREMENT_DIVERGENCE-adjacent investigation). runHandler.go's
// killInfo != nil branch used to set `ap.theExecutor = nil` BEFORE
// calling recordMetricsSync — by the time recordMetricsImpl tried to
// take its final CPU snapshot, `ap.theExecutor != nil` was already
// false, so the snapshot silently stayed at its zero value regardless
// of how much real CPU work the activation had done. Separately,
// killExecution() (cgroupFreezer.go) fully reaps the process via its
// own internal cmd.Wait() before ever returning, so even with the
// ordering fixed, a PID-based snapshot (readCPUSnapshot, which
// discovers the cgroup via /proc/{pid}/cgroup) would still fail post-
// reap — the fix reads cpu.stat directly from the activation's own
// (still-existing) cgroup path instead (readCPUSnapshotFromCgroup).
//
// This file verifies the actual, real-world consequence: a killed
// activation that did substantial, real, measurable CPU work before
// being killed must report that work (energy_attributed_uj > 0) to the
// collector — not silently 0, which is indistinguishable from "no real
// work happened" (CLAUDE.md's own "no implicit fallback" principle,
// §11) and, before the collector-side Source fix, used to also corrupt
// energy_final_uj into the raw whole-socket delta.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIncrementingFakeRAPLFile is newFakeRAPLFile's counterpart for tests
// that need a genuinely non-zero deltaRAPL: a background goroutine
// writes a steadily increasing value every 5ms until the test's own
// Cleanup stops it. The static single-write file used by most tests in
// this package (newFakeRAPLFile) always yields deltaRAPL == 0 between
// any two reads, which is fine for pure-ordering tests but useless here
// — attributedEnergyUJ() would short-circuit to 0 via its own
// deltaRAPL <= 0 check regardless of any real CPU work, defeating the
// point of this test.
func newIncrementingFakeRAPLFile(t *testing.T) string {
	t.Helper()
	f, err := ioutil.TempFile("", "fake_rapl_incrementing_*.txt")
	require.NoError(t, err)
	path := f.Name()
	require.NoError(t, f.Close())

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var value int64 = 1_000_000
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				value += 100_000
				_ = ioutil.WriteFile(path, []byte(fmt.Sprintf("%d", value)), 0644)
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})
	return path
}

// capturingCollectorServer stands in for the collector's /collect
// endpoint and decodes+stores every payload it receives, so a test can
// assert on the actual pushed values (not just "something arrived",
// newFakeCollectorServer's own concern in metricsOrdering_test.go).
type capturingCollectorServer struct {
	*httptest.Server
	mu       sync.Mutex
	payloads []collectorPayload
}

func newCapturingCollectorServer(t *testing.T) *capturingCollectorServer {
	t.Helper()
	c := &capturingCollectorServer{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p collectorPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err == nil {
			c.mu.Lock()
			c.payloads = append(c.payloads, p)
			c.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *capturingCollectorServer) runPayloads() []collectorPayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]collectorPayload, 0, len(c.payloads))
	for _, p := range c.payloads {
		if p.Endpoint == "/run" {
			out = append(out, p)
		}
	}
	return out
}

// Required test #1: an activation killed after real, measurable CPU
// work reports a non-zero energy_attributed_uj (and therefore a
// non-zero energy_final_uj downstream, per the collector-side fix) —
// not the silent 0 the pre-fix ordering bug always produced for every
// killed activation, real work or not.
func TestRunHandler_KilledActivation_WithRealCPUWork_ReportsNonZeroAttribution(t *testing.T) {
	t.Setenv("RAPL_PATH", newIncrementingFakeRAPLFile(t))
	t.Setenv("RAPL_CORES", "0") // pin to 1 core so cpuRatio isn't diluted by the host's real core count
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)

	os.RemoveAll("./action/energy_attribution_after_kill")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_attribution_after_kill", "", logf, logf)

	// Real, CPU-bound busy work (shell arithmetic, not sleep/read) — must
	// still be running when the energy threshold is reached, so the kill
	// interrupts genuine, accumulating cgroup CPU usage, exactly like the
	// real incident (reserve_stock's hashing loop, killed mid-work).
	script := []byte("#!/bin/sh\n" +
		"while read a; do\n" +
		"  i=0\n" +
		"  while [ $i -lt 100000000 ]; do i=$((i+1)); done\n" +
		"done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())

	ts := httptest.NewServer(ap)
	defer ts.Close()

	// pauseEnabled=false: the threshold is enforced by an immediate,
	// local, synchronous kill (CLAUDE.md §3.1) — no scheduler round-trip
	// needed for this test. A tiny threshold guarantees the kill fires
	// early, while the busy loop is still running, but only after at
	// least one monitor tick has observed real, non-zero CPU progress.
	requestBody := `{"value": {
		"quantity": 1,
		"energy_trace_id": "trace-kill-real-cpu",
		"energy_reservation_id": "trace-kill-real-cpu",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": 0.0005,
		"energy_consumed_before_j": 0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "",
		"energy_max_pause_duration_ms": 0,
		"energy_max_pause_count": 0,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`

	_, status, err := doPost(ts.URL+"/run", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status, "expected the kill-path's neutral failure response")

	waitFor(t, 2*time.Second, "this activation's /run metrics reached the collector", func() bool {
		return len(collector.runPayloads()) == 1
	})

	payloads := collector.runPayloads()
	require.Len(t, payloads, 1)
	p := payloads[0]

	t.Logf("killed activation payload: energy_attributed_uj=%d energy_start=%d energy_end=%d",
		p.EnergyAttributed, p.EnergyStart, p.EnergyEnd)

	// testify v1.3.0 (pinned by this repo) has no assert.Greater, hence
	// the explicit comparison (same pattern as this repo's other tests).
	assert.Truef(t, p.EnergyAttributed > 0,
		"a killed activation with real, measurable CPU work before the kill "+
			"must report a non-zero energy_attributed_uj (got %d) — the pre-fix "+
			"ordering bug (ap.theExecutor = nil before recordMetricsSync) always "+
			"reported exactly 0 here regardless of real work done", p.EnergyAttributed)
}

// Required test #3: the normal-completion path never went through the
// buggy nil-then-record ordering (ap.theExecutor is only nilled in the
// killInfo != nil branch) and must remain unaffected by this fix.
func TestRunHandler_NormalCompletion_WithRealCPUWork_StillReportsNonZeroAttribution(t *testing.T) {
	t.Setenv("RAPL_PATH", newIncrementingFakeRAPLFile(t))
	t.Setenv("RAPL_CORES", "0")

	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)

	os.RemoveAll("./action/energy_attribution_normal_completion")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_attribution_normal_completion", "", logf, logf)

	// Real CPU-bound work, but responds on its own — no threshold, no
	// kill, ordinary completion.
	script := []byte("#!/bin/sh\n" +
		"while read a; do\n" +
		"  i=0\n" +
		"  while [ $i -lt 3000000 ]; do i=$((i+1)); done\n" +
		"  echo '{\"ok\": true}' >&3\n" +
		"done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	resp, status, err := doPost(ts.URL+"/run", `{"value": {"quantity": 1}}`)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	waitFor(t, 2*time.Second, "this activation's /run metrics reached the collector", func() bool {
		return len(collector.runPayloads()) == 1
	})

	p := collector.runPayloads()[0]
	t.Logf("normal-completion payload: energy_attributed_uj=%d", p.EnergyAttributed)
	assert.Truef(t, p.EnergyAttributed > 0,
		"normal completion must still report real CPU work correctly (got %d) — no regression "+
			"expected here, but confirmed explicitly rather than assumed", p.EnergyAttributed)
}
