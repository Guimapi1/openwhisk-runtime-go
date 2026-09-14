package openwhisk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// collectorPayload correspond exactement à MetricPayload dans le collecteur.
type collectorPayload struct {
	Endpoint         string `json:"endpoint"`
	Start            int64  `json:"start"`
	End              int64  `json:"end"`
	EnergyStart      int64  `json:"energy_start"`
	EnergyEnd        int64  `json:"energy_end"`
	EnergyAttributed int64  `json:"energy_attributed_uj"`
	TraceID          string `json:"energy_trace_id"`
	PodName          string `json:"pod_name"`
	ActivationID     string `json:"activation_id"`
	// D4 (CLAUDE.md §0 decision 23, §6.10). THIS is the field that
	// actually crosses the wire — collectorPayload is a separate struct
	// from Entry and copies field by field, so an Entry field that is not
	// mirrored here never reaches the collector at all. Omitting it was a
	// real gap in the first cut of D4: Entry.ExecutionPhase was populated
	// correctly and asserted via ap.metrics (the in-process store), but
	// the collector kept receiving untagged points and defaulting every
	// compensation to "forward". omitempty mirrors Entry's own tag: an
	// unmanaged action sends no phase, which the collector resolves to
	// "forward" (executionPhaseOrDefault).
	ExecutionPhase string `json:"execution_phase,omitempty"`

	// Lifecycle (§7.9, PHASE13A). Added here for the SAME reason
	// ExecutionPhase carries the warning above: this struct — not Entry —
	// is what actually goes over the wire. A field added to Entry alone
	// is asserted green by every in-process test and still never reaches
	// the collector. That is exactly how D4 shipped broken, and how this
	// field shipped broken on its first cluster run.
	Lifecycle *Lifecycle `json:"lifecycle,omitempty"`

	// Attribution breakdown (§7.9). Troisième occurrence du même défaut que
	// les deux blocs ci-dessus : les champs avaient été ajoutés à Entry, au
	// site de remplissage (metrics_helpers.go) et au collecteur, tout était
	// vert, et ils n'ont jamais franchi le fil parce que cette struct-ci ne
	// les recopiait pas. Vérifier ici AVANT de reconstruire une image.
	CPUProcessUsec  int64   `json:"cpu_process_usec,omitempty"`
	CPUCapacityUsec int64   `json:"cpu_capacity_usec,omitempty"`
	CPURatio        float64 `json:"cpu_ratio,omitempty"`
}

// pushMetrics envoie les métriques d'une entrée vers le collecteur central.
// L'URL du collecteur est lue depuis COLLECTOR_URL (ex: http://ow-collector:9090).
func pushMetrics(endpoint string, entry Entry) {
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		log.Printf("COLLECTOR_URL not set, skipping push")
		return
	}

	payload := collectorPayload{
		Endpoint:         endpoint,
		Start:            entry.Start,
		End:              entry.End,
		EnergyStart:      entry.EnergyStart,
		EnergyEnd:        entry.EnergyEnd,
		EnergyAttributed: entry.EnergyAttributed,
		TraceID:          entry.TraceID,
		PodName:          entry.PodName,
		ActivationID:     entry.ActivationID,
		ExecutionPhase:   entry.ExecutionPhase,
		Lifecycle:        entry.Lifecycle,
		CPUProcessUsec:   entry.CPUProcessUsec,
		CPUCapacityUsec:  entry.CPUCapacityUsec,
		CPURatio:         entry.CPURatio,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("pushMetrics: marshal error: %v", err)
		return
	}

	url := fmt.Sprintf("%s/collect", strings.TrimRight(collectorURL, "/"))
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("pushMetrics: build request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pushMetrics: send error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		log.Printf("pushMetrics: unexpected status: %s", resp.Status)
		return
	}

	log.Printf("pushMetrics: sent %s activation=%s trace=%s energy_attr=%dµJ",
		endpoint, entry.ActivationID, entry.TraceID, entry.EnergyAttributed)
}
