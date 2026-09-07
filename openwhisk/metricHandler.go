package openwhisk

import (
	"encoding/json"
	"net/http"
	"sync"
)

// PauseCycle is ONE freeze -> command -> resume/kill cycle's own
// instrumentation (CLAUDE.md §7.9). An invocation contains N of these:
// max_pause_count can exceed 1, and an UNKILLABLE step re-polls inside a
// single cycle. Flattening them into the per-invocation Entry would keep
// only one, so the collector fans these out into their own measurement —
// same POST, same handler, two measurements, because the data genuinely
// has two cardinalities (PHASE13A design, §0).
type PauseCycle struct {
	PauseID string `json:"pause_id"`

	// §7.9 threshold_detected_at / energy_at_threshold: the instant the
	// monitor saw the threshold crossed, BEFORE any freeze was asked for.
	ThresholdDetectedAt float64 `json:"threshold_detected_at"`
	EnergyAtThresholdJ  float64 `json:"energy_at_threshold_j"`

	// §7.9 freeze_requested_at / freeze_effective_at. Already measured
	// before this phase (they populate EXECUTION_PAUSED, §7.6) but never
	// reached the metrics pipeline.
	FreezeRequestedAt float64 `json:"freeze_requested_at"`
	FreezeEffectiveAt float64 `json:"freeze_effective_at"`

	// §7.9 energy_at_effective_freeze. THE quantity §4.4's invariant is
	// stated on (energy_at_effective_freeze_j <= reserved_j) — until now
	// the invariant was unverifiable for lack of its own left-hand side.
	// reserved_j is scheduler-side, so the check itself needs a join on
	// pause_id; this side supplies the measurement.
	EnergyAtEffectiveFreezeJ float64 `json:"energy_at_effective_freeze_j"`

	// The threshold this cycle froze against — carried so the join above
	// has a runtime-side anchor even when scheduler logs are unavailable.
	ExecutionThresholdJ float64 `json:"execution_threshold_j"`

	// §7.9 "coût de gestion des commandes": POST EXECUTION_PAUSED sent ->
	// scheduler's command decoded. Dominated by the scheduler round-trip.
	CommandRoundtripNs int64 `json:"command_roundtrip_ns"`

	// §7.9 resume_requested_at / resume_effective_at. Zero when the cycle
	// did not end in a resume (killed, or still queued).
	ResumeRequestedAt        float64 `json:"resume_requested_at,omitempty"`
	ResumeEffectiveAt        float64 `json:"resume_effective_at,omitempty"`
	EnergyAtResumeEffectiveJ float64 `json:"energy_at_resume_effective_j,omitempty"`

	// resumed | killed | queued_wait. Low cardinality: the collector tags
	// the point with it, so a campaign can filter cycles by outcome
	// without re-deriving it from null checks.
	Outcome string `json:"outcome"`
}

// Lifecycle carries the per-INVOCATION half of §7.9 plus the N pause
// cycles. Attached to Entry by pointer with omitempty so an unmanaged
// action (no energy state at all) sends exactly what it sent before this
// phase — the same backward-compatibility contract execution_phase got.
type Lifecycle struct {
	// §7.9 "coût CPU du monitoring". Deliberately NOT named _cpu_: Go
	// exposes no per-goroutine CPU time, so this is wall time spent
	// inside the sampling body, summed over MonitorSamples iterations.
	// That is the quantity that matters for overhead, but calling it CPU
	// would overclaim what is measured.
	MonitorSamples int64 `json:"monitor_samples,omitempty"`
	MonitorBusyNs  int64 `json:"monitor_busy_ns,omitempty"`

	// §7.9 "coût du sidecar" (§7.8): extraction on the way in, reinjection
	// on the way out, and the serialized size of __energy_state — the
	// three components of what the sidecar costs a sequence per step.
	SidecarExtractNs  int64 `json:"sidecar_extract_ns,omitempty"`
	SidecarInjectNs   int64 `json:"sidecar_inject_ns,omitempty"`
	SidecarStateBytes int64 `json:"sidecar_state_bytes,omitempty"`

	// §7.9 kill_requested_at / process_stopped_at. Per-INVOCATION, not
	// per-cycle, and that placement is the point: §3.1's local kill
	// (pauseEnabled=false) happens with NO pause cycle at all, so a
	// cycle-level field would make exactly the KILL_SAFE path invisible.
	KillRequestedAt  float64 `json:"kill_requested_at,omitempty"`
	ProcessStoppedAt float64 `json:"process_stopped_at,omitempty"`

	Cycles []PauseCycle `json:"cycles,omitempty"`
}

type RunMeta struct {
	TraceID      string
	PodName      string
	ActivationID string
	// ExecutionPhase is "forward" or "recovery" (CLAUDE.md §0 decision 23,
	// §6.10). It is NOT a new concept: it is EnergyState.ExecutionPhase,
	// already carried per-step by the __energy_state sidecar (§7.8) and by
	// every runtime event (§7.6), merely propagated one step further so
	// the collector can tag the measurement point with it. Empty when this
	// invocation carries no energy state at all (an unmanaged action) —
	// the collector defaults that to "forward".
	ExecutionPhase string
	// Lifecycle is the monitor's and sidecar's §7.9 instrumentation,
	// carried to recordMetrics the same way ExecutionPhase already is.
	Lifecycle *Lifecycle
}

// Entry représente une mesure complète pour une invocation.
type Entry struct {
	Start            int64  `json:"start"`
	End              int64  `json:"end"`
	EnergyStart      int64  `json:"energy_start"`
	EnergyEnd        int64  `json:"energy_end"`
	// EnergyAttributed est la fraction d'énergie RAPL attribuée à cette action
	// via pondération CPU : delta_RAPL × (cpu_process / cpu_total).
	// Vaut 0 si l'action est trop courte (< ~10ms) ou si RAPL est indisponible.
	EnergyAttributed int64  `json:"energy_attributed_uj"`
	TraceID          string `json:"energy_trace_id"`
	PodName          string `json:"pod_name"`
	ActivationID     string `json:"activation_id"`
	// ExecutionPhase discriminates a forward invocation from a compensation
	// one (CLAUDE.md §0 decision 23, §6.10). The collector writes it as an
	// indexed TAG so get_energy_reference() can exclude recovery samples
	// from a sequence's energy reference — while get_energy_for_trace(),
	// the settlement path, keeps summing both (§4.1/§4.6: compensation
	// energy stays committed to the slot, it is only excluded from the
	// statistical reference). omitempty: an unmanaged action sends no
	// phase at all rather than an empty string.
	ExecutionPhase   string `json:"execution_phase,omitempty"`
	// Lifecycle (§7.9, PHASE13A). Pointer + omitempty: absent from the
	// JSON entirely for an unmanaged action, so the collector's existing
	// decode path is bit-for-bit unaffected.
	Lifecycle        *Lifecycle `json:"lifecycle,omitempty"`
}

// Metrics stocke pour chaque endpoint une slice d'Entry.
type Metrics struct {
	mu    sync.RWMutex
	data  map[string][]Entry
	limit int
}

func NewMetrics(limit int) *Metrics {
	return &Metrics{
		data:  make(map[string][]Entry),
		limit: limit,
	}
}

func (m *Metrics) Add(endpoint string, entry Entry) {
	if entry.Start == 0 && entry.End == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.data[endpoint]
	s = append(s, entry)
	if m.limit > 0 && len(s) > m.limit {
		s = s[len(s)-m.limit:]
	}
	m.data[endpoint] = s
}

func (m *Metrics) Snapshot() map[string][]Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]Entry, len(m.data))
	for k, v := range m.data {
		cp := make([]Entry, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func (ap *ActionProxy) metricHandler(w http.ResponseWriter, r *http.Request) {
	if ap.metrics == nil {
		http.Error(w, "metrics not initialized", http.StatusServiceUnavailable)
		return
	}
	snap := ap.metrics.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(snap)
}