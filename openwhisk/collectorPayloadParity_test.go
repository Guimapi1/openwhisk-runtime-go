package openwhisk

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// Trois fois le même défaut : un champ ajouté à Entry, rempli correctement,
// asserté vert par les tests en mémoire, et jamais transmis au collecteur
// parce que pushMetrics recopie Entry dans collectorPayload champ par champ.
// D4 (execution_phase), Lifecycle, puis les champs d'attribution CPU (§7.9).
// Ce test remplace la vigilance par une vérification : toute étiquette JSON
// portée par Entry doit exister sur collectorPayload, sinon le champ ne
// franchit pas le fil.
//
// entryOnlyFields liste les exceptions DÉLIBÉRÉES — un champ d'Entry qui
// n'a volontairement pas à être transmis. Y ajouter une entrée est une
// décision explicite ; c'est précisément ce qui manquait aux trois fois.
var entryOnlyFields = map[string]bool{}

func jsonTagSet(t *testing.T, v any) map[string]reflect.Kind {
	t.Helper()
	out := map[string]reflect.Kind{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				name = tag[:j]
				break
			}
		}
		out[name] = f.Type.Kind()
	}
	return out
}

func TestCollectorPayloadCoversEntry(t *testing.T) {
	entryTags := jsonTagSet(t, Entry{})
	payloadTags := jsonTagSet(t, collectorPayload{})

	for name, kind := range entryTags {
		if entryOnlyFields[name] {
			continue
		}
		payloadKind, ok := payloadTags[name]
		if !ok {
			t.Errorf("Entry porte %q mais collectorPayload ne le recopie pas : "+
				"le champ ne franchira jamais le fil vers le collecteur. "+
				"Ajoute-le a collectorPayload ET a la recopie dans pushMetrics, "+
				"ou declare-le dans entryOnlyFields si l'omission est voulue.", name)
			continue
		}
		if payloadKind != kind {
			t.Errorf("champ %q : Entry=%v, collectorPayload=%v (types divergents)",
				name, kind, payloadKind)
		}
	}
}

// La parité de structure ne prouve pas que pushMetrics recopie réellement la
// valeur : un champ présent des deux côtés mais absent de la recopie reste
// silencieux. Ce test-ci appelle donc la VRAIE pushMetrics et lit le corps
// HTTP effectivement émis — jamais une reconstruction du payload dans le
// test, qui n'asserterait que sa propre copie.
func TestPushMetricsCarriesAttributionOverTheWire(t *testing.T) {
	bodies := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("COLLECTOR_URL", srv.URL)

	pushMetrics("test-endpoint", Entry{
		TraceID:          "trace-parity",
		ActivationID:     "act-parity",
		EnergyAttributed: 4242,
		CPUProcessUsec:   123456,
		CPUCapacityUsec:  789012,
		CPURatio:         0.1564,
	})

	var raw []byte
	select {
	case raw = <-bodies:
	case <-time.After(5 * time.Second):
		t.Fatal("pushMetrics n'a rien emis")
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for key, want := range map[string]float64{
		"cpu_process_usec":  123456,
		"cpu_capacity_usec": 789012,
		"cpu_ratio":         0.1564,
	} {
		got, ok := decoded[key]
		if !ok {
			t.Fatalf("%q absent du corps HTTP reellement emis vers le collecteur : %s", key, raw)
		}
		if got.(float64) != want {
			t.Errorf("%q = %v, attendu %v", key, got, want)
		}
	}
}
