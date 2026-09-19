package openwhisk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
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

// metricsPushMaxAttempts lit METRICS_PUSH_MAX_ATTEMPTS (défaut 3) : nombre de tentatives d'envoi d'une mesure au
// collecteur. Même convention que executionKilledMaxAttempts (schedulerChannel.go).
func metricsPushMaxAttempts() int {
	n := 3
	if v := os.Getenv("METRICS_PUSH_MAX_ATTEMPTS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	return n
}

// metricsPushBackoffBase lit METRICS_PUSH_RETRY_BACKOFF_BASE_MS (défaut 200) : base de l'attente exponentielle entre
// deux tentatives (base * 2^(tentative-1)).
func metricsPushBackoffBase() time.Duration {
	ms := 200
	if v := os.Getenv("METRICS_PUSH_RETRY_BACKOFF_BASE_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// logSafetyMetricsUndelivered : événement [safety] critique quand une mesure n'a pu être remise au collecteur après
// toutes les tentatives. Même forme JSON que logSafetyKilledUndelivered.
func logSafetyMetricsUndelivered(endpoint string, entry Entry, attempts int, lastErr string) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":                "METRICS_PUSH_UNDELIVERED",
		"severity":             "critical",
		"endpoint":             endpoint,
		"trace_id":             entry.TraceID,
		"activation_id":        entry.ActivationID,
		"execution_phase":      entry.ExecutionPhase,
		"energy_attributed_uj": entry.EnergyAttributed,
		"attempts":             attempts,
		"last_error":           lastErr,
		"detail": "the measurement of this activation never reached the collector: settlement, which sums the " +
			"collector's points, will undercount this trace by energy_attributed_uj",
	})
	if err != nil {
		log.Printf("[safety] METRICS_PUSH_UNDELIVERED activation=%s (marshal failed: %v)", entry.ActivationID, err)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// pushMetrics envoie les métriques d'une entrée vers le collecteur central.
// L'URL du collecteur est lue depuis COLLECTOR_URL (ex: http://ow-collector:9090).
//
// Tentatives bornées (METRICS_PUSH_MAX_ATTEMPTS). Mesuré le 2026-09-19 (run b1bis, 384 req/min) : deux étapes gelées puis
// reprises n'ont laissé AUCUN point — ni mesure ni cycle de pause, qui partent dans ce même POST — alors que l'étape
// s'était terminée et avait transmis son énergie à l'étape suivante ; collecteur et InfluxDB sans erreur. Une seule
// tentative, et son échec n'était écrit que dans la sortie d'un conteneur supprimé ensuite.
// Renvoyer le MÊME corps est sans risque de double comptage : le collecteur date le point du `Start` de l'entrée et
// l'étiquette par trace, activation, conteneur et phase (les cycles, par leur ThresholdDetectedAt) ; InfluxDB réécrit
// le point de même série et même horodatage au lieu d'en ajouter un.
// Pas de reprise sur une réponse 4xx : le collecteur refuse ce corps, le renvoyer ne changerait rien.
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
	maxAttempts := metricsPushMaxAttempts()
	base := metricsPushBackoffBase()
	lastErr := "none"

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(base * time.Duration(1<<uint(attempt-1)))
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Printf("pushMetrics: build request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err.Error()
			log.Printf("pushMetrics: send attempt %d/%d failed activation=%s trace=%s: %v",
				attempt+1, maxAttempts, entry.ActivationID, entry.TraceID, err)
			continue
		}
		status := resp.StatusCode
		// Drainer avant de fermer, sinon la connexion n'est pas rendue au pool (même exigence que postExecutionKilled).
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if status == http.StatusOK || status == http.StatusAccepted {
			suffix := ""
			if attempt > 0 {
				suffix = fmt.Sprintf(" (attempt %d/%d)", attempt+1, maxAttempts)
			}
			log.Printf("pushMetrics: sent %s activation=%s trace=%s energy_attr=%dµJ%s",
				endpoint, entry.ActivationID, entry.TraceID, entry.EnergyAttributed, suffix)
			return
		}
		lastErr = fmt.Sprintf("HTTP %d", status)
		if status >= 400 && status < 500 {
			log.Printf("pushMetrics: refused activation=%s trace=%s: HTTP %d — not retried",
				entry.ActivationID, entry.TraceID, status)
			break
		}
		log.Printf("pushMetrics: attempt %d/%d activation=%s trace=%s: HTTP %d",
			attempt+1, maxAttempts, entry.ActivationID, entry.TraceID, status)
	}
	logSafetyMetricsUndelivered(endpoint, entry, maxAttempts, lastErr)
}
