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
	EnergyMethod     uint8  `json:"energy_method"`
	TraceID          string `json:"energy_trace_id"`
	PodName          string `json:"pod_name"`
	ActivationID     string `json:"activation_id"`
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
		EnergyMethod:     uint8(entry.EnergyMethod),
		TraceID:          entry.TraceID,
		PodName:          entry.PodName,
		ActivationID:     entry.ActivationID,
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