package openwhisk

// pushMetricsRetry_test.go : envoi borné des mesures au collecteur (pushgateway.go). Constat du 2026-09-19 (run b1bis,
// 384 req/min) : deux étapes gelées puis reprises n'ont laissé aucun point au collecteur, sans aucune erreur côté
// serveur ; l'envoi était unique et son échec n'était visible que dans la sortie d'un conteneur supprimé.

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedCollector struct {
	mu       sync.Mutex
	statuses []int // statut rendu à chaque requête, le dernier se répète
	bodies   [][]byte
}

func (c *scriptedCollector) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, body)
	i := len(c.bodies) - 1
	if i >= len(c.statuses) {
		i = len(c.statuses) - 1
	}
	status := c.statuses[i]
	c.mu.Unlock()
	w.WriteHeader(status)
}

func (c *scriptedCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func withPushEnv(t *testing.T, url string) *bytes.Buffer {
	t.Helper()
	for k, v := range map[string]string{"COLLECTOR_URL": url, "METRICS_PUSH_MAX_ATTEMPTS": "3",
		"METRICS_PUSH_RETRY_BACKOFF_BASE_MS": "1"} {
		old, had := os.LookupEnv(k)
		require.NoError(t, os.Setenv(k, v))
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func sampleEntry() Entry {
	return Entry{Start: 1789786212011000000, End: 1789786224336000000, EnergyAttributed: 25400000,
		TraceID: "f9c66902-c046-4e34-84be-33087e3023b0", ActivationID: "61ce68bef8ad42088e68bef8ad2208d1",
		PodName: "wskowdev-invoker-12-163-guest-ordersmoke-b1-rs535", ExecutionPhase: "forward"}
}

func TestPushMetrics_RetriesUntilAccepted_WithTheSameBody(t *testing.T) {
	c := &scriptedCollector{statuses: []int{503, 503, 200}}
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	logs := withPushEnv(t, srv.URL)

	pushMetrics("/run", sampleEntry())

	require.Equal(t, 3, c.count(), "deux refus 503 puis une acceptation : trois envois")
	assert.Equal(t, c.bodies[0], c.bodies[1])
	assert.Equal(t, c.bodies[0], c.bodies[2], "le même corps à chaque tentative : même point, réécrit par InfluxDB")
	assert.Contains(t, logs.String(), "pushMetrics: sent /run activation=61ce68bef8ad42088e68bef8ad2208d1")
	assert.Contains(t, logs.String(), "(attempt 3/3)")
	assert.NotContains(t, logs.String(), "METRICS_PUSH_UNDELIVERED")
}

func TestPushMetrics_GivesUpAfterMaxAttempts_WithASafetyEvent(t *testing.T) {
	c := &scriptedCollector{statuses: []int{503}}
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	logs := withPushEnv(t, srv.URL)

	pushMetrics("/run", sampleEntry())

	assert.Equal(t, 3, c.count())
	out := logs.String()
	require.Contains(t, out, `[safety] {"activation_id":"61ce68bef8ad42088e68bef8ad2208d1"`)
	assert.Contains(t, out, `"event":"METRICS_PUSH_UNDELIVERED"`)
	assert.Contains(t, out, `"trace_id":"f9c66902-c046-4e34-84be-33087e3023b0"`)
	assert.Contains(t, out, `"energy_attributed_uj":25400000`)
	assert.Contains(t, out, `"last_error":"HTTP 503"`)
}

func TestPushMetrics_DoesNotRetryARefusal(t *testing.T) {
	c := &scriptedCollector{statuses: []int{400}}
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	logs := withPushEnv(t, srv.URL)

	pushMetrics("/run", sampleEntry())

	assert.Equal(t, 1, c.count(), "un 4xx : le collecteur refuse ce corps, le renvoyer ne changerait rien")
	assert.Contains(t, logs.String(), "not retried")
	assert.Contains(t, logs.String(), `"last_error":"HTTP 400"`)
}

func TestPushMetrics_RetriesATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // plus personne n'écoute : échec de transport à chaque tentative
	logs := withPushEnv(t, url)

	pushMetrics("/run", sampleEntry())

	out := logs.String()
	assert.Equal(t, 3, strings.Count(out, "pushMetrics: send attempt"), out)
	assert.Contains(t, out, `"event":"METRICS_PUSH_UNDELIVERED"`)
}
