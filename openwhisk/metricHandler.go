package openwhisk

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Entry représente une paire start/end en nanosecondes.
type Entry struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
	EnergyStart int64 `json:"energy_start"`
	EnergyEnd int64 `json:"energy_end"`
	// InstructionCPU int64 `json:"instruction_cpu"`
}

// Metrics stocke pour chaque endpoint une slice d'Entry.
// Le cap (limit) évite la croissance infinie de la mémoire.
type Metrics struct {
	mu    sync.RWMutex
	data  map[string][]Entry
	limit int // nombre maximal d'entrées par endpoint
}

func NewMetrics(limit int) *Metrics {
	return &Metrics{
		data:  make(map[string][]Entry),
		limit: limit,
	}
}

// Add ajoute une paire start/end pour l'endpoint donné.
func (m *Metrics) Add(endpoint string, startNs, endNs, energyStart, energyEnd int64) {
	if startNs == 0 && endNs == 0 {
		return
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.data[endpoint]
	s = append(s, Entry{Start: startNs, End: endNs, EnergyStart: energyStart, EnergyEnd: energyEnd})
	if m.limit > 0 && len(s) > m.limit {
		s = s[len(s)-m.limit:]
	}
	m.data[endpoint] = s
}

// Snapshot retourne une copie de la map pour sérialisation JSON.
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

// metricHandler renvoie le snapshot JSON via HTTP.
// Doit être utilisé comme méthode d'ActionProxy : ap.metricHandler(w,r)
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
