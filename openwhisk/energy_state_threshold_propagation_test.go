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

// D1 (real-cluster smoke test, CLAUDE.md §7.8 point 2): the threshold
// handed to the NEXT sequence step via __energy_state must be the one in
// force after any extension granted during the previous step's pause
// cycles — not the step's initial threshold.
//
// monitorEnergy() deliberately works on a private copy of the EnergyState
// so a pause cycle never mutates the caller's struct mid-flight; but
// ReinjectEnergyState() serialises the CALLER's struct, so the extension
// was invisible to the next step. Live symptom: the scheduler granted an
// extension taking the threshold to 7.45 J, and step 2 received
// execution_threshold_j = 1.945 J alongside consumed_before_j = 5.508 J —
// a threshold it had already exceeded before doing any work. With
// max_pause_count = 1 that spurious freeze exhausts step 2's only cycle
// and triggers a fallback kill (a full compensation for a COMPENSATABLE
// action) on a sequence still inside its extended envelope. It only went
// unnoticed live because ship_order was too short (~0.014 J) to reach the
// first monitor tick.
func TestEnergyState_ExtendedThresholdPropagatesToNextStep(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	const extendedThresholdJ = 7.45

	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		// The scheduler grants an extension: resume under a HIGHER
		// threshold, exactly as extend_forward_reservation() would.
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: extendedThresholdJ,
		}
	})

	os.RemoveAll("./action/energy_threshold_propagation")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/energy_threshold_propagation", "", logf, logf)

	// Echoes its input back, so step 1's response carries __energy_state
	// and can be chained into step 2 the way OpenWhisk natively does.
	script := []byte("#!/bin/sh\nwhile read a; do sleep 0.3; echo \"{\\\"received_body\\\": $a}\" >&3 ; done\n")
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	ts := httptest.NewServer(ap)
	defer ts.Close()

	const traceID = "trace-d1-propagation"
	const initialThresholdJ = 1.0

	// Step 1: a low threshold it will cross almost immediately, so a
	// pause/extension/resume cycle really happens, then it completes
	// inside the extended envelope.
	step1Body := fmt.Sprintf(`{"value": {
		"energy_trace_id": %q,
		"energy_reservation_id": %q,
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": %v,
		"energy_consumed_before_j": %v,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 2000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`, traceID, traceID, initialThresholdJ, initialThresholdJ)

	resp1, status1, err := doPost(ts.URL+"/run", step1Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status1, "resp=%s", resp1)

	// The pause cycle must genuinely have happened, otherwise this test
	// would pass vacuously.
	require.Len(t, fs.getPausedEvents(), 1, "step 1 must have frozen once")
	require.Empty(t, fs.getKilledEvents(), "step 1 must have resumed, not been killed")

	var parsed1 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(resp1), &parsed1))
	stateRaw, ok := parsed1[energyStateKey]
	require.True(t, ok, "step 1 must reinject %s: %s", energyStateKey, resp1)

	stateBytes, err := json.Marshal(stateRaw)
	require.NoError(t, err)
	var propagated EnergyState
	require.NoError(t, json.Unmarshal(stateBytes, &propagated))

	// THE ASSERTION D1 IS ABOUT.
	assert.Equal(t, extendedThresholdJ, propagated.ExecutionThresholdJ,
		"the state handed to the next step must carry the POST-extension "+
			"threshold (%v), not the step's initial one (%v)",
		extendedThresholdJ, initialThresholdJ)
	assert.True(t, propagated.ExecutionThresholdJ > propagated.ConsumedBeforeJ,
		"the next step must not inherit a threshold it has already exceeded "+
			"(threshold=%v, consumed_before=%v)",
		propagated.ExecutionThresholdJ, propagated.ConsumedBeforeJ)

	// Step 2: fed exactly what OpenWhisk's native chaining would feed it —
	// step 1's result, __energy_state included, no top-level energy_*.
	step2Body := fmt.Sprintf(`{"value": {%q: %s}, "action_name": "action"}`,
		energyStateKey, string(stateBytes))

	resp2, status2, err := doPost(ts.URL+"/run", step2Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status2, "resp=%s", resp2)

	// Step 2 must NOT have frozen: it inherited a threshold above what the
	// sequence has consumed so far. Before the fix it froze immediately on
	// a threshold already exceeded.
	assert.Len(t, fs.getPausedEvents(), 1,
		"step 2 must not freeze on an inherited, already-exceeded threshold")
	assert.Empty(t, fs.getKilledEvents(),
		"and must certainly not be killed — the sequence is inside its extended envelope")
}

// D1 — INVARIANT GUARD. The original reason monitorEnergy() works on a
// private copy (`energy := *initialEnergy`) is that the caller's struct
// must NOT be mutated while the step is still running. The D1 fix must
// not quietly trade that away for the propagation it adds.
//
// This calls Interact() directly so the test owns the *EnergyState the
// runtime is handed, and inspects it from inside the fake scheduler's
// command callback — which runs mid-pause, with the action frozen and
// the monitor still live. At that instant the caller's struct must still
// hold the ORIGINAL threshold; only after Interact() returns may it hold
// the extended one.
//
// It also covers TWO successive pause cycles, so "last extension wins"
// is asserted rather than assumed.
func TestEnergyState_CallerStructNotMutatedUntilStepEnds(t *testing.T) {
	t.Setenv("RAPL_PATH", newFakeRAPLFile(t))
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	// The fake RAPL file is static, so attributed step energy is ~0 and a
	// crossing is driven by ConsumedBeforeJ alone. 5 J consumed against a
	// 1 J threshold freezes immediately; the first extension to 3 J is
	// still below 5 J so it freezes a SECOND time (giving the two cycles
	// this test needs); the second extension finally clears it.
	const initialThresholdJ = 1.0
	const consumedBeforeJ = 5.0
	const firstExtensionJ = 3.0
	const secondExtensionJ = 1e9 // "never freeze again", so the step completes

	energy := &EnergyState{
		TraceID:             "trace-d1-invariant",
		ReservationID:       "trace-d1-invariant",
		ExecutionPhase:      "forward",
		ExecutionThresholdJ: initialThresholdJ,
		ConsumedBeforeJ:     consumedBeforeJ,
		PauseEnabled:        true,
		PauseMode:           "CGROUP_FREEZE",
		MaxPauseDurationMs:  2000,
		MaxPauseCount:       2,
		InterruptionClass:   map[string]string{"action": "KILL_SAFE"},
		ResolvedActionName:  "action",
	}

	var observedDuringPause []float64
	var mu sync.Mutex
	cycle := 0

	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		// Runs WHILE the action is frozen and the monitor is alive.
		mu.Lock()
		observedDuringPause = append(observedDuringPause, energy.ExecutionThresholdJ)
		cycle++
		next := firstExtensionJ
		if cycle > 1 {
			next = secondExtensionJ
		}
		mu.Unlock()
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
			ReservationID: ev.ReservationID, PauseID: ev.PauseID,
			NewExecutionThresholdJ: next,
		}
	})

	os.RemoveAll("./action/d1_invariant")
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy("./action/d1_invariant", "", logf, logf)

	script := []byte(sleepThenRespondScriptContent("0.4"))
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	defer ap.theExecutor.Stop()

	_, _, killInfo := ap.theExecutor.Interact([]byte("{}"), energy)
	require.Nil(t, killInfo, "the step must have resumed, not been killed")

	mu.Lock()
	seen := append([]float64(nil), observedDuringPause...)
	mu.Unlock()

	require.Len(t, seen, 2,
		"two pause cycles must have happened, otherwise \"last extension wins\" "+
			"below would pass by accident rather than by design")
	for i, v := range seen {
		assert.Equal(t, initialThresholdJ, v,
			"pause cycle %d observed the CALLER's struct already mutated to %v — "+
				"monitorEnergy()'s private-copy invariant has been broken", i+1, v)
	}

	// Only now, with the monitor stopped, is the settled value published —
	// and it is the LAST extension granted, not the first.
	assert.Equal(t, secondExtensionJ, energy.ExecutionThresholdJ,
		"after Interact() returns, the caller's struct must carry the final threshold")
}
