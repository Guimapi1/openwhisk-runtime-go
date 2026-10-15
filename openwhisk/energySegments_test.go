/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openwhisk

// CLAUDE.md §0 décision 44 : l'énergie d'une étape est attribuée par
// segments d'exécution. Deux niveaux de tests :
//   - le calcul seul, sur des relevés construits (pas de processus) ;
//   - de bout en bout, avec un vrai gel de cgroup, un faux scheduler qui
//     tarde à répondre et un faux compteur RAPL qui s'emballe PENDANT le gel
//     — c'est-à-dire d'autres conteneurs très actifs sur le même nœud.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// snap : relevé CPU à `wallS` secondes, après `cpuS` secondes de temps CPU.
func snap(wallS, cpuS float64) CPUSnapshot {
	return CPUSnapshot{ProcessTicks: int64(cpuS * 1e6), WallNs: int64(wallS * 1e9)}
}

func joules(j float64) int64 { return int64(j * 1e6) }

// Une seconde active (100 J au nœud, 0,5 s de CPU), deux secondes gelées
// (énergie du nœud : paramètre), une seconde active (100 J, 0,5 s de CPU).
// Un seul cœur : chaque segment actif vaut 100 J × 0,5 = 50 J.
func etapeGelee(nodeEnergyWhileFrozenJ float64) (int64, int64, CPUSnapshot, CPUSnapshot, []freezeMark) {
	e0 := joules(1000)
	eFreeze := e0 + joules(100)
	eResume := eFreeze + joules(nodeEnergyWhileFrozenJ)
	eEnd := eResume + joules(100)
	marks := []freezeMark{{
		FreezeEnergyUJ: eFreeze, FreezeCPU: snap(1, 0.5),
		Resumed: true, ResumeEnergyUJ: eResume, ResumeCPU: snap(3, 0.5),
	}}
	return e0, eEnd, snap(0, 0), snap(4, 1.0), marks
}

func TestSegmentedAttribution_WithoutAFreezeIsTheWholeIntervalFormula(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	whole := attributionDetail(joules(1000), joules(1300), snap(0, 0), snap(4, 1.0))
	require.Equal(t, joules(75), whole.AttributedUJ, "300 J × 1 s de CPU sur 4 s")

	assert.Equal(t, whole, segmentedAttribution(joules(1000), joules(1300), snap(0, 0), snap(4, 1.0), nil),
		"une étape jamais gelée a un seul segment : sa mesure ne change pas")
	assert.Equal(t, whole, segmentedAttribution(joules(1000), joules(1300), snap(0, 0), snap(4, 1.0), []freezeMark{}))
}

func TestSegmentedAttribution_NothingIsAttributedBetweenFreezeAndResume(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	e0, eEnd, s0, sEnd, marks := etapeGelee(1000)

	got := segmentedAttribution(e0, eEnd, s0, sEnd, marks)

	assert.Equal(t, joules(100), got.AttributedUJ, "deux segments de 50 J")
	assert.Equal(t, int64(1_000_000), got.DeltaProcessUsec)
	assert.Equal(t, int64(2_000_000), got.CapacityUsec, "la capacité ne compte pas les 2 s gelées")
	assert.Equal(t, 0.5, got.CPURatio)

	// Ce que donnait l'attribution d'un seul tenant : 1 200 J × 1 s / 4 s. Les
	// 1 000 J brûlés par les AUTRES conteneurs pendant le gel entraient dans
	// l'énergie de cette étape.
	assert.Equal(t, joules(300), attributionDetail(e0, eEnd, s0, sEnd).AttributedUJ)
}

func TestSegmentedAttribution_DoesNotDependOnNodePowerDuringTheFreeze(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	for _, frozenJ := range []float64{0, 10, 1000, 100000} {
		e0, eEnd, s0, sEnd, marks := etapeGelee(frozenJ)
		assert.Equal(t, joules(100), segmentedAttribution(e0, eEnd, s0, sEnd, marks).AttributedUJ,
			"énergie du nœud pendant le gel : %.0f J", frozenJ)
	}
}

func TestSegmentedAttribution_KilledWhileFrozenStopsAtTheEffectiveFreeze(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	e0 := joules(1000)
	marks := []freezeMark{{FreezeEnergyUJ: e0 + joules(100), FreezeCPU: snap(1, 0.5)}} // jamais reprise

	// Le relevé de fin est pris après le kill, 2,5 s et 5 000 J plus tard.
	got := segmentedAttribution(e0, e0+joules(5100), snap(0, 0), snap(3.5, 0.5), marks)

	assert.Equal(t, joules(50), got.AttributedUJ, "réglée à son énergie au gel effectif")
	assert.Equal(t, int64(1_000_000), got.CapacityUsec)
}

func TestSegmentedAttribution_SeveralPauseCycles(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	e := joules(1000)
	marks := []freezeMark{
		{FreezeEnergyUJ: e + joules(100), FreezeCPU: snap(1, 0.5), Resumed: true,
			ResumeEnergyUJ: e + joules(900), ResumeCPU: snap(2, 0.5)},
		{FreezeEnergyUJ: e + joules(960), FreezeCPU: snap(3, 1.0), Resumed: true,
			ResumeEnergyUJ: e + joules(2000), ResumeCPU: snap(5, 1.0)},
	}

	got := segmentedAttribution(e, e+joules(2040), snap(0, 0), snap(6, 1.25), marks)

	// 100 J × 0,5 + 60 J × 0,5 + 40 J × 0,25
	assert.Equal(t, joules(50+30+10), got.AttributedUJ)
	assert.Equal(t, int64(1_250_000), got.DeltaProcessUsec)
	assert.Equal(t, int64(3_000_000), got.CapacityUsec)
}

func TestStepMeter_FrozenEnergyDoesNotMoveAndResumeOpensANewSegment(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	e := joules(1000)
	meter := newStepMeter(e, snap(0, 0))
	assert.InDelta(t, 25.0, meter.stepJ(e+joules(50), snap(0.5, 0.25)), 1e-9)

	meter.closeAt(e+joules(100), snap(1, 0.5))
	require.True(t, meter.frozen)
	assert.InDelta(t, 50.0, meter.closedJ(), 1e-9)
	// Gelé : le nœud brûle 1 000 J de plus, l'énergie de l'étape ne bouge pas.
	assert.InDelta(t, 50.0, meter.stepJ(e+joules(1100), snap(3, 0.5)), 1e-9)

	meter.openAt(e+joules(1100), snap(3, 0.5))
	require.False(t, meter.frozen)
	assert.InDelta(t, 50.0+50.0, meter.stepJ(e+joules(1200), snap(4, 1.0)), 1e-9)
}

func TestFreezeMarks_ResetAndResumeOnlyCompletesAnOpenFreeze(t *testing.T) {
	var marks freezeMarks
	marks.noteResume(1, snap(1, 0)) // aucune marque ouverte : ignoré
	assert.Empty(t, marks.snapshot())

	marks.noteFreeze(10, snap(1, 0.5))
	marks.noteResume(20, snap(2, 0.5))
	marks.noteResume(99, snap(9, 0.5)) // déjà reprise : ignoré
	got := marks.snapshot()
	require.Len(t, got, 1)
	assert.True(t, got[0].Resumed)
	assert.Equal(t, int64(20), got[0].ResumeEnergyUJ)

	marks.reset()
	assert.Empty(t, marks.snapshot())
}

// Le compteur de temps CPU était en retard au relevé du gel : ce qu'il compte
// ensuite, pendant le gel, complète le segment clos. L'instant et l'énergie
// du gel effectif ne changent pas, donc l'énergie suit le temps CPU.
func TestStepMeter_RefineFrozenCPU_CompletesTheClosedSegment(t *testing.T) {
	t.Setenv("RAPL_CORES", "0")
	e := joules(1000)
	meter := newStepMeter(e, snap(0, 0))
	assert.Equal(t, int64(0), meter.refineFrozenCPU(999_999), "sans gel en cours : rien")

	meter.closeAt(e+joules(100), snap(1, 0.5)) // 100 J × 0,5 s ÷ 1 s
	assert.InDelta(t, 50.0, meter.closedJ(), 1e-9)

	assert.Equal(t, int64(100_000), meter.refineFrozenCPU(600_000)) // 0,1 s compté en retard
	assert.InDelta(t, 60.0, meter.closedJ(), 1e-9, "100 J × 0,6 s ÷ 1 s")
	assert.Equal(t, int64(0), meter.refineFrozenCPU(600_000), "même relevé : rien de plus")
	assert.Equal(t, int64(0), meter.refineFrozenCPU(550_000), "un relevé plus bas est ignoré")
	assert.InDelta(t, 60.0, meter.closedJ(), 1e-9)
	assert.InDelta(t, 60.0, meter.stepJ(e+joules(5000), snap(3, 0.6)), 1e-9, "toujours gelé : l'énergie ne bouge pas")

	// Le segment suivant repart du temps CPU du gel complété : rien n'est perdu, rien n'est compté deux fois.
	meter.openAt(e+joules(1100), snap(3, 0.6))
	assert.InDelta(t, 60.0+50.0, meter.stepJ(e+joules(1200), snap(4, 1.1)), 1e-9)
	assert.Equal(t, int64(0), meter.refineFrozenCPU(2_000_000), "après la reprise : rien")
}

func TestFreezeMarks_RefineOnlyRaisesTheCPUOfAnOpenFreeze(t *testing.T) {
	var marks freezeMarks
	marks.refineFreezeCPU(123) // aucune marque : ignoré
	assert.Empty(t, marks.snapshot())

	marks.noteFreeze(10, snap(1, 0.5))
	marks.refineFreezeCPU(400_000) // plus bas : ignoré
	assert.Equal(t, int64(500_000), marks.snapshot()[0].FreezeCPU.ProcessTicks)
	marks.refineFreezeCPU(520_000)
	got := marks.snapshot()[0]
	assert.Equal(t, int64(520_000), got.FreezeCPU.ProcessTicks)
	assert.Equal(t, int64(1e9), got.FreezeCPU.WallNs, "l'instant du gel effectif ne change pas")
	assert.Equal(t, int64(10), got.FreezeEnergyUJ, "l'énergie au gel effectif ne change pas")

	marks.noteResume(20, snap(2, 0.52))
	marks.refineFreezeCPU(900_000) // déjà reprise : ignoré
	assert.Equal(t, int64(520_000), marks.snapshot()[0].FreezeCPU.ProcessTicks)
}

// fauxConteneur : un Executor dont le cgroup et le compteur d'énergie du nœud
// sont deux fichiers que le test écrit. Aucun processus, aucun vrai gel : on
// y rejoue exactement ce que le noyau a montré sur grappe.
type fauxConteneur struct {
	t       *testing.T
	proc    *Executor
	cpuStat string
	rapl    string
}

func newFauxConteneur(t *testing.T) *fauxConteneur {
	t.Helper()
	dir := t.TempDir()
	f := &fauxConteneur{t: t, cpuStat: dir + "/cpu.stat", rapl: dir + "/energy_uj"}
	t.Setenv("RAPL_PATH", f.rapl)
	t.Setenv("RAPL_CORES", "0")
	f.proc = &Executor{controller: &ActivationController{cg: &cgroupHandle{path: dir}}, marks: &freezeMarks{}}
	f.set(joules(1000), 0)
	return f
}

func (f *fauxConteneur) set(energyUJ, cpuUsec int64) {
	f.t.Helper()
	require.NoError(f.t, ioutil.WriteFile(f.rapl, []byte(fmt.Sprintf("%d\n", energyUJ)), 0644))
	require.NoError(f.t, ioutil.WriteFile(f.cpuStat, []byte(fmt.Sprintf("usage_usec %d\nuser_usec 0\nsystem_usec 0\n", cpuUsec)), 0644))
}

// Ce que la grappe a montré le 2026-10-11 : le compteur de temps CPU du
// conteneur avance encore après la confirmation du gel. Ce temps ne doit être
// perdu ni compté deux fois, et le moniteur et la mesure finale doivent dire
// la même chose.
func TestFrozenSegment_CPUCountedAfterTheFreezeConfirmation_IsNeitherLostNorCountedTwice(t *testing.T) {
	f := newFauxConteneur(t)
	energyStart, cpuStart, err := f.proc.segmentSnapshot()
	require.NoError(t, err)
	meter := newStepMeter(energyStart, cpuStart)

	_, ok := f.proc.refineFrozenSegment(meter)
	assert.False(t, ok, "étape non gelée : rien à compléter")

	time.Sleep(20 * time.Millisecond)
	f.set(joules(1002), 10_000) // gel effectif : 10 ms de CPU lus
	require.True(t, f.proc.closeSegmentAtFreeze(meter, "trace", "pause"))
	auGel := meter.closedJ()
	require.True(t, auGel > 0)

	// Pendant le gel : le nœud brûle 50 J pour d'autres, et le noyau finit
	// de compter 400 µs que le conteneur avait consommées avant de geler.
	f.set(joules(1052), 10_400)
	late, ok := f.proc.refineFrozenSegment(meter)
	require.True(t, ok)
	assert.Equal(t, int64(400), late, "le contrôle du gel : temps CPU compté depuis le relevé du gel effectif")
	assert.InDelta(t, auGel*1.04, meter.closedJ(), 3e-6, "même énergie du nœud, même durée, 4 %% de temps CPU en plus")
	marks := f.proc.FreezeMarks()
	require.Len(t, marks, 1)
	assert.Equal(t, int64(10_400), marks[0].FreezeCPU.ProcessTicks)
	late, ok = f.proc.refineFrozenSegment(meter)
	assert.True(t, ok)
	assert.Equal(t, int64(0), late, "rien de plus au second relevé")

	// Dégel : quand le relevé de reprise est pris, le conteneur a déjà recalculé 50 µs.
	f.set(joules(1052), 10_450)
	require.True(t, f.proc.openSegmentAtResume(meter, "trace", "pause"))
	assert.Equal(t, int64(10_400), meter.segCPU.ProcessTicks, "le segment suivant repart du temps CPU du gel")
	marks = f.proc.FreezeMarks()
	require.True(t, marks[0].Resumed)
	assert.Equal(t, int64(10_400), marks[0].ResumeCPU.ProcessTicks)
	_, ok = f.proc.refineFrozenSegment(meter)
	assert.False(t, ok, "étape reprise : rien à compléter")

	time.Sleep(20 * time.Millisecond)
	f.set(joules(1054), 30_000) // fin de l'étape
	energyEnd, cpuEnd, err := f.proc.segmentSnapshot()
	require.NoError(t, err)

	detail := segmentedAttribution(energyStart, energyEnd, cpuStart, cpuEnd, marks)
	assert.Equal(t, int64(30_000), detail.DeltaProcessUsec, "tout le temps CPU de l'étape, une fois et une seule")
	assert.InDelta(t, float64(detail.AttributedUJ)/1e6, meter.stepJ(energyEnd, cpuEnd), 3e-6,
		"le moniteur et la mesure finale attribuent la même énergie")
	// L'énergie du nœud pendant le gel (50 J) n'est attribuée à personne : l'étape reste sous les 4 J de ses segments.
	assert.True(t, detail.AttributedUJ < joules(4), "énergie attribuée : %d µJ", detail.AttributedUJ)
}

// Étape tuée pendant son gel : elle est réglée à l'énergie de son segment clos, temps CPU compté en retard compris.
func TestFrozenSegment_KilledWhileFrozen_IsSettledWithTheCompletedSegment(t *testing.T) {
	f := newFauxConteneur(t)
	energyStart, cpuStart, err := f.proc.segmentSnapshot()
	require.NoError(t, err)
	meter := newStepMeter(energyStart, cpuStart)
	time.Sleep(20 * time.Millisecond)
	f.set(joules(1002), 10_000)
	require.True(t, f.proc.closeSegmentAtFreeze(meter, "trace", "pause"))
	f.set(joules(1052), 10_250)
	// Juste avant le kill, comme le fait le moniteur : le cycle de pause reçoit le contrôle du gel et
	// l'énergie au gel effectif du segment complété.
	cycle := PauseCycle{EnergyAtEffectiveFreezeJ: 7.0 + meter.closedJ()}
	avant := meter.closedJ()
	f.proc.refineCycleWhileFrozen(meter, &cycle, 7.0)
	require.NotNil(t, cycle.CPUUsecWhileFrozen)
	assert.Equal(t, int64(250), *cycle.CPUUsecWhileFrozen)
	assert.True(t, meter.closedJ() > avant, "le segment clos a reçu le temps CPU compté en retard")
	assert.InDelta(t, 7.0+meter.closedJ(), cycle.EnergyAtEffectiveFreezeJ, 1e-12,
		"le cycle porte l'énergie du segment complété, cumul des étapes précédentes compris")

	// Après le kill : le nœud continue de brûler, le cgroup ne compte plus rien.
	f.set(joules(1100), 10_250)
	energyEnd, cpuEnd, err := f.proc.segmentSnapshot()
	require.NoError(t, err)
	detail := segmentedAttribution(energyStart, energyEnd, cpuStart, cpuEnd, f.proc.FreezeMarks())
	assert.Equal(t, int64(10_250), detail.DeltaProcessUsec)
	assert.InDelta(t, meter.closedJ(), float64(detail.AttributedUJ)/1e6, 3e-6,
		"l'énergie réglée est celle du gel effectif, que le moniteur a envoyée dans EXECUTION_KILLED")
}

// §0 décision 46 (2026-10-15) : EXECUTION_PAUSED porte le cumul de la phase au GEL EFFECTIF (§7.5 étapes 5 et 6,
// §5.1), pas celui de la détection du seuil. Entre les deux, le conteneur a encore calculé : le faux conteneur avance
// l'énergie du nœud et le temps CPU entre le relevé de la détection et celui du gel.
func TestPauseCycle_PausedEventCarriesTheCumulativeAtTheEffectiveFreeze(t *testing.T) {
	f := newFauxConteneur(t)
	dir := filepath.Dir(f.cpuStat)
	events := filepath.Join(dir, "cgroup.events")
	require.NoError(t, ioutil.WriteFile(events, []byte("populated 1\nfrozen 1\n"), 0644)) // relu par le gel
	f.proc.controller = &ActivationController{cg: &cgroupHandle{path: dir}, state: StateRunning, waiter: &waitOnce{}}
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		// relu par le dégel ; rien d'autre ne change pendant le gel
		require.NoError(t, ioutil.WriteFile(events, []byte("populated 1\nfrozen 0\n"), 0644))
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID, ReservationID: ev.ReservationID,
			PauseID: ev.PauseID, NewExecutionThresholdJ: 99,
		}
	})

	energyStart, cpuStart, err := f.proc.segmentSnapshot()
	require.NoError(t, err)
	meter := newStepMeter(energyStart, cpuStart)
	time.Sleep(20 * time.Millisecond)
	f.set(joules(1002), 10_000) // détection du seuil
	energyAt, cpuAt, err := f.proc.segmentSnapshot()
	require.NoError(t, err)
	stepAtDetectionJ := meter.stepJ(energyAt, cpuAt)
	require.True(t, stepAtDetectionJ > 0)
	time.Sleep(20 * time.Millisecond)
	f.set(joules(1003), 15_000) // le gel effectif vient après : le conteneur a encore calculé

	energy := &EnergyState{
		TraceID: "t", ReservationID: "t", ExecutionPhase: "forward",
		ExecutionThresholdJ: 7.0 + stepAtDetectionJ, ConsumedBeforeJ: 7.0,
		PauseEnabled: true, PauseMode: "CGROUP_FREEZE", MaxPauseDurationMs: 2000, MaxPauseCount: 1,
		InterruptionClass: map[string]string{"action": "KILL_SAFE"},
	}
	result := &energyMonitorResult{}
	newThresholdJ, killed, _ := f.proc.runPauseCycle(
		energy, "action", stepAtDetectionJ, result, time.Now(), 7.0+stepAtDetectionJ, meter)
	require.False(t, killed)
	assert.Equal(t, 99.0, newThresholdJ)

	paused := fs.getPausedEvents()
	require.Len(t, paused, 1)
	require.Len(t, result.lifecycle.Cycles, 1)
	cycle := result.lifecycle.Cycles[0]
	assert.InDelta(t, 7.0+meter.closedJ(), paused[0].EnergyConsumedJ, 1e-12,
		"le signalement porte le cumul au gel effectif : cumul des étapes précédentes et segment clos au gel")
	assert.Equal(t, cycle.EnergyAtEffectiveFreezeJ, paused[0].EnergyConsumedJ)
	assert.Equal(t, 7.0+stepAtDetectionJ, cycle.EnergyAtThresholdJ)
	assert.True(t, paused[0].EnergyConsumedJ-cycle.EnergyAtThresholdJ > 1e-6,
		"et non le cumul à la détection : %.9f J au gel, %.9f J à la détection",
		paused[0].EnergyConsumedJ, cycle.EnergyAtThresholdJ)
}

// --- De bout en bout -----------------------------------------------------

// rateControlledRAPL : faux compteur d'énergie du nœud, incrémenté toutes les
// 2 ms à `base` µJ par tick, multiplié par `burst` quand celui-ci est levé.
type rateControlledRAPL struct {
	path  string
	burst int64 // 0 ou 1, atomique
}

const (
	raplTick       = 2 * time.Millisecond
	raplBaseUJ     = 40_000 // par tick : 20 J/s
	raplBurstTimes = 50     // pendant un gel : 1 000 J/s
)

func newRateControlledRAPL(t *testing.T) *rateControlledRAPL {
	t.Helper()
	f, err := ioutil.TempFile("", "fake_rapl_rate_*.txt")
	require.NoError(t, err)
	_, err = f.WriteString("1000000")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	r := &rateControlledRAPL{path: f.Name()}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		value := int64(1_000_000)
		last := time.Now()
		ticker := time.NewTicker(raplTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				// Au temps écoulé, pas au nombre de ticks : un ticker en retard ne ralentit pas le compteur.
				rate := float64(raplBaseUJ) / raplTick.Seconds()
				if atomic.LoadInt64(&r.burst) == 1 {
					rate *= raplBurstTimes
				}
				value += int64(rate * now.Sub(last).Seconds())
				last = now
				// Écriture atomique (fichier voisin puis renommage) : un lecteur ne voit jamais un fichier
				// tronqué. Un compteur RAPL réel ne se lit jamais à moitié ; une lecture vide ferait rendre
				// zéro à tout le calcul d'attribution, et le test mesurerait son propre faux compteur.
				tmp := r.path + ".tmp"
				if ioutil.WriteFile(tmp, []byte(fmt.Sprintf("%d", value)), 0644) == nil {
					_ = os.Rename(tmp, r.path)
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
		os.Remove(r.path)
		os.Remove(r.path + ".tmp")
	})
	return r
}

func (r *rateControlledRAPL) setBurst(on bool) {
	v := int64(0)
	if on {
		v = 1
	}
	atomic.StoreInt64(&r.burst, v)
}

// Corps de requête d'une première étape gelable : rien de consommé avant,
// seuil à thresholdJ.
func freezableRequestBody(traceID string, thresholdJ float64) string {
	return `{"value": {
		"energy_trace_id": "` + traceID + `",
		"energy_reservation_id": "` + traceID + `",
		"energy_execution_phase": "forward",
		"energy_execution_threshold_j": ` + jsonFloat(thresholdJ) + `,
		"energy_consumed_before_j": 0,
		"energy_pause_enabled": true,
		"energy_pause_mode": "CGROUP_FREEZE",
		"energy_max_pause_duration_ms": 5000,
		"energy_max_pause_count": 1,
		"energy_interruption_class": {"action": "KILL_SAFE"}
	}, "action_name": "action"}`
}

// Travail lié au calcul (arithmétique du shell), puis une réponse.
func busyThenRespondScript(iterations int) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\nwhile read a; do\n  i=0\n  while [ $i -lt %d ]; do i=$((i+1)); done\n"+
		"  echo '{\"ok\": true}' >&3\ndone\n", iterations))
}

const frozenHold = 600 * time.Millisecond

func startBusyAction(t *testing.T, dir string, iterations int) (*ActionProxy, *httptest.Server) {
	t.Helper()
	os.RemoveAll(dir)
	logf, err := ioutil.TempFile("/tmp", "log")
	require.NoError(t, err)
	ap := NewActionProxy(dir, "", logf, logf)
	script := busyThenRespondScript(iterations)
	_, err = ap.ExtractAction(&script, "bin")
	require.NoError(t, err)
	require.NoError(t, ap.StartLatestAction())
	ts := httptest.NewServer(ap)
	t.Cleanup(ts.Close)
	return ap, ts
}

// Une étape gelée 600 ms pendant que le reste du nœud consomme cinquante
// fois plus. Avant la décision 44, cette énergie entrait dans la mesure de
// l'étape (attribution d'un seul tenant) : la borne ci-dessous était
// dépassée d'un ordre de grandeur.
func TestRunHandler_FrozenStep_IsNotChargedForNodeEnergyDuringTheFreeze(t *testing.T) {
	rapl := newRateControlledRAPL(t)
	t.Setenv("RAPL_PATH", rapl.path)
	t.Setenv("RAPL_CORES", "0")
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "5")
	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		rapl.setBurst(true) // les autres conteneurs s'emballent pendant le gel
		time.Sleep(frozenHold)
		rapl.setBurst(false)
		return SchedulerCommand{
			Command: "RESUME_EXECUTION", TraceID: ev.TraceID, ReservationID: ev.ReservationID,
			PauseID: ev.PauseID, NewExecutionThresholdJ: 1e9,
		}
	})
	ap, ts := startBusyAction(t, "./action/segments_frozen_resumed", 400000)
	defer ap.theExecutor.Stop()

	resp, status, err := doPost(ts.URL+"/run", freezableRequestBody("trace-seg-resume", 0.5))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "resp=%s", resp)

	payloads := collector.runPayloads()
	require.Len(t, payloads, 1)
	p := payloads[0]
	require.NotNil(t, p.Lifecycle)
	require.Len(t, p.Lifecycle.Cycles, 1, "un cycle de pause attendu")
	cycle := p.Lifecycle.Cycles[0]
	require.Equal(t, "resumed", cycle.Outcome)

	frozenS := cycle.ResumeEffectiveAt - cycle.FreezeEffectiveAt
	require.True(t, frozenS >= frozenHold.Seconds()*0.9,
		"le gel doit durer le temps de la réponse du scheduler : %.3f s", frozenS)

	// Aucune énergie n'est attribuée au gel.
	assert.Equal(t, cycle.EnergyAtEffectiveFreezeJ, cycle.EnergyAtResumeEffectiveJ)
	// Le contrôle du gel : temps CPU compté entre le relevé du gel effectif et le dernier relevé avant le
	// dégel. Un conteneur gelé ne calcule pas ; il peut rester un retard de comptabilité du noyau, d'un tick au plus.
	require.NotNil(t, cycle.CPUUsecWhileFrozen, "le temps CPU pendant le gel doit être mesuré")
	assert.True(t, *cycle.CPUUsecWhileFrozen <= 5000,
		"un cgroup gelé ne consomme pas de CPU : %d µs en %.3f s de gel", *cycle.CPUUsecWhileFrozen, frozenS)

	// Borne : même à 100 % d'un cœur, l'étape ne peut pas se voir attribuer
	// plus que l'énergie du nœud pendant son temps ACTIF, au débit de base.
	attributedJ := float64(p.EnergyAttributed) / 1e6
	baseJPerS := float64(raplBaseUJ) / raplTick.Seconds() / 1e6
	activeS := float64(p.End-p.Start)/1e9 - frozenS
	require.True(t, activeS > 0.0)
	bound := baseJPerS * activeS * 1.25
	assert.True(t, attributedJ > 0.5, "l'étape a franchi son seuil de 0,5 J : %.3f J attribués", attributedJ)
	// Et elle a travaillé APRÈS la reprise : son énergie ne s'arrête pas au gel. Une boucle de calcul occupe un
	// cœur ; 30 % du débit de base sur son temps actif est un plancher large.
	floor := baseJPerS * activeS * 0.3
	assert.True(t, attributedJ >= floor,
		"énergie attribuée %.2f J pour %.2f s actives (plancher %.2f J) : le segment d'après la reprise manque",
		attributedJ, activeS, floor)
	assert.True(t, attributedJ <= bound,
		"énergie attribuée %.2f J pour %.2f s actives (borne %.2f J) : l'énergie du nœud pendant le gel "+
			"(%.0f J) ne doit pas y entrer", attributedJ, activeS, bound, baseJPerS*raplBurstTimes*frozenS)

	// Le sidecar transmet la même énergie à l'étape suivante (consumed_before_j).
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(resp), &parsed))
	var state map[string]interface{}
	require.NoError(t, json.Unmarshal(parsed[energyStateKey], &state))
	sidecarJ, ok := state["consumed_before_j"].(float64)
	require.True(t, ok, "état transmis : %v", state)
	assert.True(t, sidecarJ <= bound, "énergie transmise à l'étape suivante : %.2f J (borne %.2f J)", sidecarJ, bound)
	assert.InDelta(t, attributedJ, sidecarJ, 0.25*attributedJ+0.1)

	assert.Empty(t, fs.getKilledEvents())
}

// Une étape gelée puis tuée par le scheduler est réglée à son énergie au gel
// effectif, quoi que le nœud ait consommé pendant qu'elle attendait.
func TestRunHandler_StepKilledAfterAFreeze_IsSettledAtItsEnergyAtTheEffectiveFreeze(t *testing.T) {
	rapl := newRateControlledRAPL(t)
	t.Setenv("RAPL_PATH", rapl.path)
	t.Setenv("RAPL_CORES", "0")
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "5")
	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)
	fs := newFakeSchedulerServer(t)
	fs.setCommandFunc(func(ev ExecutionPausedEvent) SchedulerCommand {
		rapl.setBurst(true)
		time.Sleep(frozenHold)
		rapl.setBurst(false)
		return SchedulerCommand{
			Command: "KILL_EXECUTION", TraceID: ev.TraceID, ReservationID: ev.ReservationID,
			PauseID: ev.PauseID, Reason: "EXTENSION_TIMEOUT",
		}
	})
	_, ts := startBusyAction(t, "./action/segments_frozen_killed", 100000000)

	_, status, err := doPost(ts.URL+"/run", freezableRequestBody("trace-seg-kill", 0.5))
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	payloads := collector.runPayloads()
	require.Len(t, payloads, 1)
	p := payloads[0]
	require.NotNil(t, p.Lifecycle)
	require.Len(t, p.Lifecycle.Cycles, 1)
	cycle := p.Lifecycle.Cycles[0]
	require.Equal(t, "killed", cycle.Outcome)
	require.NotNil(t, cycle.CPUUsecWhileFrozen, "le contrôle du gel est relevé juste avant le kill")
	assert.True(t, *cycle.CPUUsecWhileFrozen <= 5000,
		"un cgroup gelé ne consomme pas de CPU : %d µs comptées depuis le relevé du gel", *cycle.CPUUsecWhileFrozen)
	frozenJ := cycle.EnergyAtEffectiveFreezeJ
	require.True(t, frozenJ > 0.5, "énergie au gel effectif : %.3f J", frozenJ)

	// L'événement de kill porte l'énergie au gel effectif…
	killed := fs.getKilledEvents()
	require.Len(t, killed, 1)
	assert.Equal(t, frozenJ, killed[0].EnergyConsumedJ)

	// … et la mesure envoyée au collecteur aussi : même intervalle, à l'écart près entre le relevé de début
	// de la requête et celui du moniteur. Pendant les 600 ms de gel, le nœud a brûlé plusieurs centaines de joules.
	attributedJ := float64(p.EnergyAttributed) / 1e6
	assert.InDelta(t, frozenJ, attributedJ, 0.25*frozenJ+0.1,
		"mesure finale %.2f J pour %.2f J au gel effectif", attributedJ, frozenJ)
}

// Les marques de gel sont celles d'UNE invocation : la suivante, servie par
// le même conteneur, repart sans marque. Sinon son énergie serait calculée
// depuis la reprise de l'invocation précédente.
func TestRunHandler_FreezeMarksDoNotLeakIntoTheNextInvocation(t *testing.T) {
	rapl := newRateControlledRAPL(t)
	t.Setenv("RAPL_PATH", rapl.path)
	t.Setenv("RAPL_CORES", "0")
	t.Setenv("ENERGY_MONITOR_INTERVAL_MS", "5")
	collector := newCapturingCollectorServer(t)
	t.Setenv("COLLECTOR_URL", collector.URL)
	newFakeSchedulerServer(t) // répond RESUME_EXECUTION aussitôt
	ap, ts := startBusyAction(t, "./action/segments_two_invocations", 300000)
	defer ap.theExecutor.Stop()

	_, status, err := doPost(ts.URL+"/run", freezableRequestBody("trace-seg-first", 0.5))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, ap.theExecutor.FreezeMarks(), 1, "la première invocation a été gelée une fois")

	// Seconde invocation du même conteneur : seuil jamais atteint, aucun gel.
	_, status, err = doPost(ts.URL+"/run", freezableRequestBody("trace-seg-second", 1e9))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	assert.Empty(t, ap.theExecutor.FreezeMarks())

	payloads := collector.runPayloads()
	require.Len(t, payloads, 2)
	second := payloads[1]
	attributedJ := float64(second.EnergyAttributed) / 1e6
	baseJPerS := float64(raplBaseUJ) / raplTick.Seconds() / 1e6
	bound := baseJPerS * float64(second.End-second.Start) / 1e9 * 1.25
	assert.True(t, attributedJ > 0.5, "la seconde invocation a travaillé : %.3f J", attributedJ)
	assert.True(t, attributedJ <= bound, "seconde invocation : %.2f J attribués, borne %.2f J", attributedJ, bound)
}
