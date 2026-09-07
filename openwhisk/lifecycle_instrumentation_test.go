package openwhisk

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// PHASE13A (CLAUDE.md §7.9). These cover the accumulation contract of the
// lifecycle block — that every exit path of a pause cycle records one,
// that a kill with NO pause cycle (§3.1) is still measurable, and above
// all that an unmanaged action serialises exactly what it did before this
// phase. That last one is the regression these tests exist for: the
// backward-compatibility promise is in the wire format, not in the struct.

func TestLifecycleAbsentForUnmonitoredAction(t *testing.T) {
	r := &energyMonitorResult{}
	if got := r.snapshotLifecycle(); got != nil {
		t.Fatalf("expected nil lifecycle when nothing was instrumented, got %+v", got)
	}
	// The wire format is the actual contract: an unmanaged action must
	// serialise byte-for-byte as before, i.e. with no "lifecycle" key.
	b, err := json.Marshal(Entry{Start: 1, End: 2})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if s := string(b); contains(s, "lifecycle") {
		t.Fatalf("unmanaged Entry must not carry a lifecycle key, got %s", s)
	}
}

func TestLifecycleRecordsMonitoringCost(t *testing.T) {
	r := &energyMonitorResult{}
	r.noteSample(1500 * time.Nanosecond)
	r.noteSample(2500 * time.Nanosecond)

	lc := r.snapshotLifecycle()
	if lc == nil {
		t.Fatal("expected a lifecycle once samples were recorded")
	}
	if lc.MonitorSamples != 2 {
		t.Fatalf("MonitorSamples = %d, want 2", lc.MonitorSamples)
	}
	if lc.MonitorBusyNs != 4000 {
		t.Fatalf("MonitorBusyNs = %d, want 4000", lc.MonitorBusyNs)
	}
}

func TestLifecycleRecordsKillWithoutAnyPauseCycle(t *testing.T) {
	// CLAUDE.md §3.1: pauseEnabled=false kills locally with no pause
	// cycle at all. This is exactly why kill timestamps live at the
	// invocation level — at cycle level this path would be invisible,
	// and it is the KILL_SAFE path the campaign has to measure.
	r := &energyMonitorResult{}
	req := time.Unix(1000, 0)
	stop := time.Unix(1000, 500000000)
	r.noteKill(req, stop)

	lc := r.snapshotLifecycle()
	if lc == nil {
		t.Fatal("a kill alone must still produce a lifecycle")
	}
	if len(lc.Cycles) != 0 {
		t.Fatalf("no pause cycle expected on the §3.1 path, got %d", len(lc.Cycles))
	}
	if lc.KillRequestedAt != 1000.0 {
		t.Fatalf("KillRequestedAt = %v, want 1000.0", lc.KillRequestedAt)
	}
	if lc.ProcessStoppedAt != 1000.5 {
		t.Fatalf("ProcessStoppedAt = %v, want 1000.5", lc.ProcessStoppedAt)
	}
}

func TestLifecycleAccumulatesEveryCycleOutcome(t *testing.T) {
	// The whole reason for the fan-out: N cycles per invocation. A
	// flattened representation would keep only one of these.
	r := &energyMonitorResult{}
	r.addCycle(PauseCycle{PauseID: "p1", Outcome: "resumed", EnergyAtEffectiveFreezeJ: 5.0})
	r.addCycle(PauseCycle{PauseID: "p2", Outcome: "queued_wait"})
	r.addCycle(PauseCycle{PauseID: "p3", Outcome: "killed"})

	lc := r.snapshotLifecycle()
	if len(lc.Cycles) != 3 {
		t.Fatalf("expected 3 cycles preserved, got %d", len(lc.Cycles))
	}
	for i, want := range []string{"resumed", "queued_wait", "killed"} {
		if lc.Cycles[i].Outcome != want {
			t.Fatalf("cycle %d outcome = %q, want %q", i, lc.Cycles[i].Outcome, want)
		}
	}
}

func TestLifecycleSnapshotIsACopy(t *testing.T) {
	// The monitor goroutine keeps appending after Interact() reads; a
	// shared backing array would race.
	r := &energyMonitorResult{}
	r.addCycle(PauseCycle{PauseID: "p1"})
	lc := r.snapshotLifecycle()
	r.addCycle(PauseCycle{PauseID: "p2"})

	if len(lc.Cycles) != 1 {
		t.Fatalf("snapshot must not observe later appends, got %d cycles", len(lc.Cycles))
	}
}

func TestLifecycleSerialisesAllTimestamps(t *testing.T) {
	// Guards the wire contract the collector depends on: if a JSON tag
	// is renamed, the collector silently stops seeing the field — the
	// exact failure mode that made D4 inoperative in production.
	e := Entry{Lifecycle: &Lifecycle{
		MonitorSamples: 3,
		Cycles: []PauseCycle{{
			PauseID:                  "p1",
			ThresholdDetectedAt:      100.0,
			EnergyAtThresholdJ:       4.0,
			FreezeRequestedAt:        100.1,
			FreezeEffectiveAt:        100.2,
			EnergyAtEffectiveFreezeJ: 4.2,
			ExecutionThresholdJ:      5.0,
			ResumeRequestedAt:        101.0,
			ResumeEffectiveAt:        101.1,
			EnergyAtResumeEffectiveJ: 4.2,
			Outcome:                  "resumed",
		}},
	}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		"lifecycle", "monitor_samples", "cycles", "pause_id",
		"threshold_detected_at", "energy_at_threshold_j",
		"freeze_requested_at", "freeze_effective_at",
		"energy_at_effective_freeze_j", "execution_threshold_j",
		"resume_requested_at", "resume_effective_at",
		"energy_at_resume_effective_j", "outcome",
	} {
		if !contains(string(b), key) {
			t.Fatalf("serialised Entry is missing %q: %s", key, b)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// ── Ce que pushMetrics envoie RÉELLEMENT sur le réseau ────────────────
//
// Les tests ci-dessus assertent sur Entry — l'entité en processus. C'est
// insuffisant, et ça a échoué en conditions réelles : pushMetrics ne
// sérialise pas Entry, il recopie champ par champ dans collectorPayload.
// Un champ ajouté à Entry seul passe donc tous les tests en processus et
// n'atteint jamais le collecteur. C'est ainsi que D4 a été livré cassé
// (voir le commentaire de ExecutionPhase dans pushgateway.go), et ainsi
// que ce champ-ci l'a été à sa première exécution sur cluster.
//
// Ces tests interceptent le POST lui-même. C'est le seul niveau où la
// garantie « la donnée traverse les trois composants » est vérifiable
// côté runtime.

func TestPushMetricsSendsLifecycleOverTheWire(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	t.Setenv("COLLECTOR_URL", srv.URL)

	pushMetrics("/run", Entry{
		Start: 1, End: 2, TraceID: "trace-wire",
		Lifecycle: &Lifecycle{
			MonitorSamples:   7,
			SidecarExtractNs: 1200,
			Cycles: []PauseCycle{{
				PauseID:                  "pause-wire",
				ThresholdDetectedAt:      500.0,
				EnergyAtThresholdJ:       3.0,
				FreezeEffectiveAt:        500.2,
				EnergyAtEffectiveFreezeJ: 3.1,
				Outcome:                  "resumed",
			}},
		},
	})

	if len(received) == 0 {
		t.Fatal("collector received nothing")
	}
	var decoded struct {
		Lifecycle *Lifecycle `json:"lifecycle"`
	}
	if err := json.Unmarshal(received, &decoded); err != nil {
		t.Fatalf("collector could not decode the payload: %v (%s)", err, received)
	}
	if decoded.Lifecycle == nil {
		t.Fatalf("lifecycle never reached the wire: %s", received)
	}
	if decoded.Lifecycle.MonitorSamples != 7 {
		t.Fatalf("MonitorSamples = %d, want 7", decoded.Lifecycle.MonitorSamples)
	}
	if len(decoded.Lifecycle.Cycles) != 1 {
		t.Fatalf("cycles on the wire = %d, want 1", len(decoded.Lifecycle.Cycles))
	}
	if got := decoded.Lifecycle.Cycles[0].PauseID; got != "pause-wire" {
		t.Fatalf("pause_id on the wire = %q, want pause-wire", got)
	}
	if got := decoded.Lifecycle.Cycles[0].EnergyAtEffectiveFreezeJ; got != 3.1 {
		t.Fatalf("energy_at_effective_freeze_j on the wire = %v, want 3.1", got)
	}
}

func TestPushMetricsOmitsLifecycleForUnmanagedAction(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	t.Setenv("COLLECTOR_URL", srv.URL)

	pushMetrics("/run", Entry{Start: 1, End: 2, TraceID: "trace-legacy"})

	if contains(string(received), "lifecycle") {
		t.Fatalf("an unmanaged action must send no lifecycle key: %s", received)
	}
}
