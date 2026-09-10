package openwhisk

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Ces tests verrouillent le correctif de LIMITE_KILL_NON_CONFIRME.md : la
// livraison de EXECUTION_KILLED etait un unique POST fire-and-forget dont le
// code de statut n'etait meme pas lu. Un seul echec — delai depasse, hoquet
// reseau, scheduler momentanement sature — orphelinait la reservation pour
// toujours (4 runs de s05 sur 4, 2026-09-07).
//
// Sonde de revert : revenir au POST unique sans verification de statut fait
// echouer les trois tests ci-dessous.

func withKilledEnv(t *testing.T, attempts, backoffMs string) {
	t.Helper()
	t.Setenv("EXECUTION_KILLED_MAX_ATTEMPTS", attempts)
	t.Setenv("EXECUTION_KILLED_RETRY_BACKOFF_BASE_MS", backoffMs)
}

func captureLogs(fn func()) string {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func killedEvent() ExecutionKilledEvent {
	return ExecutionKilledEvent{
		Event:                "EXECUTION_KILLED",
		TraceID:              "trace-livraison",
		ReservationID:        "trace-livraison",
		ActionName:           "bench_killsafe",
		ExecutionPhase:       "forward",
		EnergyBudgetExceeded: true,
		EnergyConsumedJ:      7.9,
	}
}

// Une panne transitoire ne doit plus perdre l'evenement : c'est tout l'objet
// du correctif.
func TestExecutionKilledRetriedAfterTransientFailures(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 : transitoire
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("SCHEDULER_URL", srv.URL)
	withKilledEnv(t, "5", "1")

	out := captureLogs(func() { postExecutionKilled(killedEvent()) })

	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("attendu 3 tentatives (2 echecs puis succes), obtenu %d", got)
	}
	if strings.Contains(out, "EXECUTION_KILLED_UNDELIVERED") {
		t.Fatalf("livraison finalement reussie : aucun incident ne doit etre emis.\n%s", out)
	}
}

// Une livraison definitivement perdue doit desormais LE DIRE. Avant le
// correctif, elle ne laissait qu'une ligne de log ordinaire — invisible en
// pratique, les journaux d'un conteneur dont l'activation est terminee ne
// remontant pas a l'invoker.
func TestExecutionKilledUndeliveredEmitsSafetyIncident(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("SCHEDULER_URL", srv.URL)
	withKilledEnv(t, "3", "1")

	out := captureLogs(func() { postExecutionKilled(killedEvent()) })

	if got := atomic.LoadInt32(&n); got != 3 {
		t.Fatalf("attendu 3 tentatives avant abandon, obtenu %d", got)
	}
	for _, attendu := range []string{
		"[safety]", "EXECUTION_KILLED_UNDELIVERED", "critical",
		"trace-livraison", "\"attempts\":3",
	} {
		if !strings.Contains(out, attendu) {
			t.Fatalf("incident [safety] incomplet, %q absent de :\n%s", attendu, out)
		}
	}
}

// Un 4xx est un REFUS du scheduler : reessayer un corps identique ne peut pas
// changer sa reponse, et ne ferait que retarder l'incident qui le signale.
func TestExecutionKilledNotRetriedOnClientError(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv("SCHEDULER_URL", srv.URL)
	withKilledEnv(t, "5", "1")

	out := captureLogs(func() { postExecutionKilled(killedEvent()) })

	if got := atomic.LoadInt32(&n); got != 1 {
		t.Fatalf("un 4xx ne doit PAS etre reessaye : %d tentatives", got)
	}
	if !strings.Contains(out, "EXECUTION_KILLED_UNDELIVERED") {
		t.Fatalf("un refus definitif doit tout de meme emettre l'incident :\n%s", out)
	}
}

// Le code de statut doit etre LU : avant le correctif, `defer resp.Body.Close()`
// etait la seule chose qui en etait faite, donc un 500 passait pour un succes.
func TestExecutionKilledStatusIsActuallyChecked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("SCHEDULER_URL", srv.URL)
	withKilledEnv(t, "1", "1")

	out := captureLogs(func() { postExecutionKilled(killedEvent()) })
	if !strings.Contains(out, "EXECUTION_KILLED_UNDELIVERED") {
		t.Fatalf("un 500 doit etre traite comme un echec, pas comme un succes :\n%s", out)
	}
	_ = os.Getenv("SCHEDULER_URL")
}
