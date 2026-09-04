package openwhisk

import (
	"encoding/json"
	"net/http"
	"sync"
)

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