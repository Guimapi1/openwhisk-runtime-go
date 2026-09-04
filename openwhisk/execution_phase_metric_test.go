package openwhisk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D4 (real-cluster smoke test, CLAUDE.md §0 decision 23, §6.10): a
// compensation's measurement point must reach the collector tagged
// execution_phase="recovery", so the scheduler can keep that energy out of
// the SEQUENCE's energy reference (never out of its settlement).
//
// EnergyState.ExecutionPhase already existed and was already set correctly
// by the scheduler on both dispatch paths — it simply stopped at the
// runtime and never made it into the pushed Entry, so the collector had no
// way to tell a compensation apart from a forward step.
func TestRunHandler_RecoveryInvocation_TagsMetricWithExecutionPhase(t *testing.T) {
	os.RemoveAll("./action/energy_phase_recovery")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_phase_recovery", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	const traceID = "trace-recovery-phase"

	// A compensation dispatch, exactly as core/scheduler.py sends it
	// (energy_execution_phase = "recovery", §6.8).
	body := fmt.Sprintf(`{"value": {
		"order_id": "o-1",
		"energy_trace_id": %q,
		"energy_reservation_id": %q,
		"energy_execution_phase": "recovery",
		"energy_execution_threshold_j": 25.5,
		"energy_consumed_before_j": 0.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 500,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"release_stock": "KILL_SAFE"}
	}}`, traceID, traceID)

	_, status, err := doPost(ts.URL+"/run", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	snap := ap.metrics.Snapshot()
	entries := snap["/run"]
	require.Len(t, entries, 1)
	assert.Equal(t, traceID, entries[0].TraceID)
	assert.Equal(t, "recovery", entries[0].ExecutionPhase,
		"a compensation's metric point must be tagged recovery — otherwise the "+
			"collector defaults it to forward and its energy pollutes the "+
			"sequence's energy reference (D4)")
}

// Symmetric control: a normal forward invocation must still be tagged
// forward, so the filter added to get_energy_reference() does not silently
// drop ordinary samples.
func TestRunHandler_ForwardInvocation_TagsMetricWithExecutionPhase(t *testing.T) {
	os.RemoveAll("./action/energy_phase_forward")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_phase_forward", "", logf, logf)

	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	const traceID = "trace-forward-phase"
	body := fmt.Sprintf(`{"value": {
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

	_, status, err := doPost(ts.URL+"/run", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	snap := ap.metrics.Snapshot()
	require.Len(t, snap["/run"], 1)
	assert.Equal(t, "forward", snap["/run"][0].ExecutionPhase)
}

// ──────────────────────────────────────────────────────────────────────
// D4 — WIRE-LEVEL coverage of BOTH pushed points (/init and /run).
//
// These assert on the JSON actually POSTed to the collector, not on
// ap.metrics. That distinction is not pedantry: collectorPayload
// (pushgateway.go) is a SEPARATE struct from Entry and copies field by
// field, so an Entry field missing from it never leaves the runtime.
// The first cut of D4 populated Entry.ExecutionPhase correctly and was
// green against ap.metrics while the collector still received untagged
// points — exactly the contamination D4 exists to remove.
//
// They also pin down the /init question precisely. /init builds its own
// RunMeta (initHandler.go) with NO phase, and ap.metrics stores that
// un-backfilled COPY. But the point that is PUSHED is pendingInitEntry,
// backfilled from the following /run — so a real /init reaching the
// collector is tagged EXPLICITLY, never by default. The default is only
// ever exercised by an invocation carrying no energy state at all.
// ──────────────────────────────────────────────────────────────────────

type capturedPush struct {
	mu       sync.Mutex
	payloads []map[string]interface{}
}

func (c *capturedPush) add(p map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.payloads = append(c.payloads, p)
}

func (c *capturedPush) byEndpoint(ep string) []map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]interface{}
	for _, p := range c.payloads {
		if p["endpoint"] == ep {
			out = append(out, p)
		}
	}
	return out
}

// newCapturingCollector stands in for the real collector and records
// every /collect body.
func newCapturingCollector(t *testing.T) (*capturedPush, *httptest.Server) {
	t.Helper()
	cap := &capturedPush{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		cap.add(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return cap, srv
}

func runOneInvocationCapturingPushes(t *testing.T, dir, body string) *capturedPush {
	t.Helper()
	cap, srv := newCapturingCollector(t)
	t.Setenv("COLLECTOR_URL", srv.URL)

	os.RemoveAll("./action/" + dir)
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/"+dir, "", logf, logf)

	ts := httptest.NewServer(ap)
	defer ts.Close()

	// The REAL two-request flow. /init is what produces the pending init
	// measurement point; calling ExtractAction/StartLatestAction directly
	// (as most tests here do) bypasses initHandler and never creates one.
	script := []byte("#!/bin/sh\nwhile read a; do echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	res, initStatus, err := doPost(ts.URL+"/init", initBytes(script, ""))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, initStatus, "init failed: %s", res)
	defer ap.theExecutor.Stop()

	_, status, err := doPost(ts.URL+"/run", body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	return cap
}

func energyBody(traceID, phase string) string {
	return fmt.Sprintf(`{"value": {
		"energy_trace_id": %q,
		"energy_reservation_id": %q,
		"energy_execution_phase": %q,
		"energy_execution_threshold_j": 55.0,
		"energy_consumed_before_j": 0.0,
		"energy_pause_enabled": false,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 500,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`, traceID, traceID, phase)
}

func TestPushedPayload_RecoveryInvocation_BothRunAndInitTaggedRecovery(t *testing.T) {
	cap := runOneInvocationCapturingPushes(t, "push_phase_recovery",
		energyBody("trace-push-recovery", "recovery"))

	runs := cap.byEndpoint("/run")
	require.Len(t, runs, 1)
	assert.Equal(t, "recovery", runs[0]["execution_phase"],
		"the /run point must cross the wire tagged recovery")

	inits := cap.byEndpoint("/init")
	require.Len(t, inits, 1, "the /init point must be pushed alongside the first /run")
	assert.Equal(t, "recovery", inits[0]["execution_phase"],
		"the /init point of a COMPENSATION container must be tagged recovery too — "+
			"left untagged it would default to forward at read time and its energy "+
			"would leak into the sequence's forward reference (D4)")
	// Backfill really happened: /init has no trace_id of its own either.
	assert.Equal(t, "trace-push-recovery", inits[0]["energy_trace_id"])
}

func TestPushedPayload_ForwardInvocation_BothRunAndInitTaggedForwardExplicitly(t *testing.T) {
	cap := runOneInvocationCapturingPushes(t, "push_phase_forward",
		energyBody("trace-push-forward", "forward"))

	runs := cap.byEndpoint("/run")
	require.Len(t, runs, 1)
	assert.Equal(t, "forward", runs[0]["execution_phase"])

	inits := cap.byEndpoint("/init")
	require.Len(t, inits, 1)
	// ANSWER TO THE /init QUESTION: explicitly tagged, not defaulted.
	assert.Equal(t, "forward", inits[0]["execution_phase"],
		"a forward /init is tagged EXPLICITLY (backfilled from its /run), it does "+
			"not rely on the collector's untagged->forward default")
}

func TestPushedPayload_NoEnergyState_OmitsPhaseAndRelisOnCollectorDefault(t *testing.T) {
	// An invocation the scheduler does not manage: no energy_* params at
	// all. This is the ONLY case that legitimately reaches the collector
	// untagged, and omitempty must keep the key absent rather than
	// sending "" (which would create a third tag bucket matching neither
	// the forward filter nor a recovery one).
	cap := runOneInvocationCapturingPushes(t, "push_phase_none",
		`{"value": {"quantity": 3}, "action_name": "action"}`)

	runs := cap.byEndpoint("/run")
	require.Len(t, runs, 1)
	_, present := runs[0]["execution_phase"]
	assert.False(t, present,
		"an unmanaged invocation must omit execution_phase entirely (omitempty), "+
			"letting executionPhaseOrDefault() resolve it to forward")
}
