package openwhisk

import (
	"os"
	"testing"
	"time"
)

// Verrouille la CAUSE RACINE du kill non confirme (LIMITE_KILL_NON_CONFIRME.md,
// etablie le 2026-09-10 par vidage de piles sur un conteneur bloque).
//
// `exited` est un canal non bufferise a UN emetteur et PLUSIEURS receveurs
// (Interact, Exited, le chemin sans ack de Start, l'initialisation). Signale
// par un ENVOI, il n'en debloquait qu'UN SEUL. Avec `concurrency: 5`, trois
// activations partageaient le meme Executor : une seule sortait de son
// `select`, les deux autres n'atteignaient jamais postExecutionKilled, et la
// trace restait a jamais non reglee cote scheduler.
//
// Sonde de revert : remplacer `close(proc.exited)` par `proc.exited <- true`
// fait echouer les deux tests ci-dessous.

func attendreSortie(t *testing.T, proc *Executor) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if proc.Exited() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("le processus n'est jamais sorti")
}

// Exited() faisait une reception NON BLOQUANTE : chaque appel CONSOMMAIT le
// jeton unique. Deux appels successifs devaient donc rendre true puis false,
// et le second appelant affamait le premier.
func TestExitedResteVraiApresPlusieursAppels(t *testing.T) {
	// Un processus qui vit PLUS longtemps que DefaultTimeoutStart : avec
	// /bin/true, Start(false) rend « command exited » parce que le process
	// est deja mort quand il regarde — et un `Skipf` la-dessus ferait passer
	// un test qui ne teste rien.
	proc := NewExecutor(os.Stdout, os.Stderr, "/bin/sleep", map[string]string{}, "1")
	if err := proc.Start(false); err != nil {
		t.Fatalf("Start a echoue : %v", err)
	}
	attendreSortie(t, proc)
	for i := 1; i <= 3; i++ {
		if !proc.Exited() {
			t.Fatalf("Exited() a rendu false au %d-eme appel : le jeton a ete "+
				"consomme au lieu d'etre diffuse a tous", i)
		}
	}
}

// Le vrai defaut : PLUSIEURS receveurs simultanes doivent TOUS etre
// debloques par la sortie du processus, pas un seul.
func TestSortieDebloqueTousLesReceveurs(t *testing.T) {
	// Un processus qui vit PLUS longtemps que DefaultTimeoutStart : avec
	// /bin/true, Start(false) rend « command exited » parce que le process
	// est deja mort quand il regarde — et un `Skipf` la-dessus ferait passer
	// un test qui ne teste rien.
	proc := NewExecutor(os.Stdout, os.Stderr, "/bin/sleep", map[string]string{}, "1")
	if err := proc.Start(false); err != nil {
		t.Fatalf("Start a echoue : %v", err)
	}
	attendreSortie(t, proc)

	const receveurs = 3
	vus := make(chan int, receveurs)
	for i := 0; i < receveurs; i++ {
		go func(n int) {
			select {
			case <-proc.exited:
				vus <- n
			case <-time.After(3 * time.Second):
			}
		}(i)
	}
	debloques := 0
	for i := 0; i < receveurs; i++ {
		select {
		case <-vus:
			debloques++
		case <-time.After(4 * time.Second):
		}
	}
	if debloques != receveurs {
		t.Fatalf("%d receveur(s) debloque(s) sur %d — avec un ENVOI un seul "+
			"l'est, et c'est exactement ce qui laissait les activations "+
			"concurrentes bloquees pour toujours", debloques, receveurs)
	}
}
