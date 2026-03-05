package openwhisk

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// pushMetrics envoie les métriques d'une entrée vers le Pushgateway via l'API text/plain.
// Format Pushgateway :
//   POST /metrics/job/<job>/instance/<instance>/activation_id/<id>/trace_id/<trace>/container_id/<container>

func pushMetrics(endpoint string, entry Entry) {
	pushgatewayURL := os.Getenv("PUSHGATEWAY_URL")
	if pushgatewayURL == "" {
		log.Printf("PUSHGATEWAY_URL not set, skipping push")
		return
	}

	// normaliser l'endpoint pour en faire un nom de métrique valide : /init -> init, /run -> run
	endpointName := strings.TrimPrefix(endpoint, "/")

	// construire les labels de grouping dans l'URL
	PodName := entry.PodName
	if PodName == "" {
		PodName = "unknown"
	}
	activationID := entry.ActivationID
	if activationID == "" {
		activationID = "unknown"
	}
	traceID := entry.TraceID
	if traceID == "" {
		traceID = "none"
	}

	url := fmt.Sprintf(
		"%s/metrics/job/openwhisk_runtime/instance/%s/activation_id/%s/trace_id/%s/endpoint/%s",
		strings.TrimRight(pushgatewayURL, "/"),
		PodName,
		activationID,
		traceID,
		endpointName,
	)

	// corps au format text/plain exposition (Prometheus text format)
	body := fmt.Sprintf(`# HELP ow_start_ns Timestamp de début en nanosecondes
# TYPE ow_start_ns gauge
ow_start_ns %d

# HELP ow_end_ns Timestamp de fin en nanosecondes
# TYPE ow_end_ns gauge
ow_end_ns %d

# HELP ow_energy_start_uj Energie RAPL au début en microjoules
# TYPE ow_energy_start_uj gauge
ow_energy_start_uj %d

# HELP ow_energy_end_uj Energie RAPL à la fin en microjoules
# TYPE ow_energy_end_uj gauge
ow_energy_end_uj %d
`,
		entry.Start,
		entry.End,
		entry.EnergyStart,
		entry.EnergyEnd,
	)

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		log.Printf("pushMetrics: failed to build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "text/plain; version=0.0.4")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pushMetrics: failed to push to %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		log.Printf("pushMetrics: unexpected status from Pushgateway: %s", resp.Status)
		return
	}

	log.Printf("pushMetrics: pushed %s metrics for activation %s (trace: %s)", endpointName, activationID, traceID)
}