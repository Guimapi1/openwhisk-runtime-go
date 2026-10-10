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

// energySegments.go — CLAUDE.md §0 décision 44 : l'énergie d'une étape est
// attribuée par SEGMENTS D'EXÉCUTION. Un gel effectif clôt le segment en
// cours, une reprise effective en ouvre un nouveau, et aucune énergie n'est
// attribuée entre les deux. L'énergie de l'étape est la somme de ses
// segments, chacun calculé par la formule de §10 (attributionDetail :
// énergie du nœud sur le segment × part de temps CPU du conteneur).
//
// Pourquoi. L'attribution se faisait d'un seul tenant sur toute l'étape,
// gels compris. Pendant un gel, le temps CPU du conteneur ne bouge plus mais
// l'intervalle s'allonge : le résultat suit la puissance moyenne du nœud,
// donc l'activité des AUTRES conteneurs. Mesuré en campagne 8 (job
// 4180123) : trois traces gelées 2,5 s pendant une montée de charge, à
// 0,94–0,96 de leur réservation au gel effectif, réglées à 1,07–1,09.
//
// Une étape jamais gelée a un seul segment : sa mesure est inchangée, au
// microjoule près (segmentedAttribution rend alors attributionDetail).
//
// Trois calculs partagent ces segments :
//   - le moniteur (stepMeter) : énergie courante de l'étape, comparée au seuil ;
//   - le sidecar (runHandler.go) : consumed_before_j transmis à l'étape suivante ;
//   - la mesure finale (recordMetricsImpl) : ce que le collecteur reçoit.
// Les deux derniers lisent les marques posées par le moniteur (freezeMarks).

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// freezeMark : relevés pris au gel effectif d'un cycle de pause et, si
// l'étape a repris, à sa reprise effective. Compteurs absolus (RAPL en µJ,
// usage_usec du cgroup, horloge) : ils se combinent avec n'importe quel
// relevé de début ou de fin d'étape.
type freezeMark struct {
	FreezeEnergyUJ int64
	FreezeCPU      CPUSnapshot
	Resumed        bool
	ResumeEnergyUJ int64
	ResumeCPU      CPUSnapshot
}

// freezeMarks : marques de gel de l'invocation en cours. Écrites par le
// moniteur (runPauseCycle), lues en fin d'étape une fois le moniteur arrêté ;
// le verrou couvre la visibilité entre goroutines.
type freezeMarks struct {
	mu    sync.Mutex
	marks []freezeMark
}

func (f *freezeMarks) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marks = nil
}

func (f *freezeMarks) noteFreeze(energyUJ int64, cpu CPUSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marks = append(f.marks, freezeMark{FreezeEnergyUJ: energyUJ, FreezeCPU: cpu})
}

// noteResume complète la dernière marque. Sans marque de gel ouverte, ne fait rien.
func (f *freezeMarks) noteResume(energyUJ int64, cpu CPUSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.marks); n > 0 && !f.marks[n-1].Resumed {
		f.marks[n-1].Resumed = true
		f.marks[n-1].ResumeEnergyUJ = energyUJ
		f.marks[n-1].ResumeCPU = cpu
	}
}

func (f *freezeMarks) snapshot() []freezeMark {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]freezeMark(nil), f.marks...)
}

// segmentedAttribution : énergie attribuée à une étape de (energyStart,
// snapStart) à (energyEnd, snapEnd), gels exclus. Sans marque, c'est
// exactement attributionDetail. Une étape encore gelée à la fin (tuée
// pendant son gel) s'arrête à son dernier gel effectif : elle est réglée à
// son énergie au gel effectif.
//
// Les entrées du modèle sont agrégées sur les segments : temps CPU et
// capacité s'additionnent, cpu_ratio est leur rapport. La capacité ne
// compte donc plus le temps passé gelé.
func segmentedAttribution(energyStart, energyEnd int64, snapStart, snapEnd CPUSnapshot, marks []freezeMark) AttributionBreakdown {
	if len(marks) == 0 {
		return attributionDetail(energyStart, energyEnd, snapStart, snapEnd)
	}
	var total AttributionBreakdown
	add := func(d AttributionBreakdown) {
		total.AttributedUJ += d.AttributedUJ
		total.DeltaProcessUsec += d.DeltaProcessUsec
		total.CapacityUsec += d.CapacityUsec
	}
	curEnergy, curCPU := energyStart, snapStart
	running := true
	for _, m := range marks {
		add(attributionDetail(curEnergy, m.FreezeEnergyUJ, curCPU, m.FreezeCPU))
		if !m.Resumed {
			running = false
			break
		}
		curEnergy, curCPU = m.ResumeEnergyUJ, m.ResumeCPU
	}
	if running {
		add(attributionDetail(curEnergy, energyEnd, curCPU, snapEnd))
	}
	if total.CapacityUsec > 0 {
		total.CPURatio = float64(total.DeltaProcessUsec) / float64(total.CapacityUsec)
		if total.CPURatio > 1.0 {
			total.CPURatio = 1.0
		}
	}
	return total
}

// stepMeter : énergie de l'étape vue du moniteur, par segments. closedUJ
// porte les segments clos ; (segEnergy, segCPU) est le début du segment en
// cours. Gelé, le compteur ne bouge plus.
type stepMeter struct {
	closedUJ  int64
	segEnergy int64
	segCPU    CPUSnapshot
	frozen    bool
	// Relevés du gel en cours : servent à mesurer le temps CPU consommé
	// pendant le gel, et de repli si le relevé de reprise échoue.
	frozenEnergy int64
	frozenCPU    CPUSnapshot
}

func newStepMeter(energyStart int64, cpuStart CPUSnapshot) *stepMeter {
	return &stepMeter{segEnergy: energyStart, segCPU: cpuStart}
}

// stepJ : énergie de l'étape à l'instant du relevé (energyNow, cpuNow).
func (m *stepMeter) stepJ(energyNow int64, cpuNow CPUSnapshot) float64 {
	if m.frozen {
		return m.closedJ()
	}
	return float64(m.closedUJ+attributedEnergyUJ(m.segEnergy, energyNow, m.segCPU, cpuNow)) / 1e6
}

// closedJ : énergie des segments clos — celle de l'étape tant qu'elle est gelée.
func (m *stepMeter) closedJ() float64 {
	return float64(m.closedUJ) / 1e6
}

func (m *stepMeter) closeAt(energyUJ int64, cpu CPUSnapshot) {
	m.closedUJ += attributedEnergyUJ(m.segEnergy, energyUJ, m.segCPU, cpu)
	m.frozen, m.frozenEnergy, m.frozenCPU = true, energyUJ, cpu
}

func (m *stepMeter) openAt(energyUJ int64, cpu CPUSnapshot) {
	m.segEnergy, m.segCPU, m.frozen = energyUJ, cpu, false
}

// segmentSnapshot lit le compteur d'énergie et le temps CPU du conteneur au
// même instant. Le temps CPU est lu par le chemin du cgroup de l'activation
// quand il est connu : c'est le fichier que lit la mesure finale, et il
// reste lisible quel que soit l'état du processus.
func (proc *Executor) segmentSnapshot() (int64, CPUSnapshot, error) {
	energyUJ, err := readEnergy()
	if path := proc.CgroupPath(); path != "" {
		return energyUJ, readCPUSnapshotFromCgroup(path), err
	}
	return energyUJ, readCPUSnapshot(proc.Pid()), err
}

// closeSegmentAtFreeze : à appeler une fois le cgroup confirmé gelé. Clôt le
// segment du moniteur et pose la marque de gel. Rend false si le relevé est
// inutilisable : aucune marque n'est alors posée, et ce cycle reste mesuré
// d'un seul tenant, comme avant la décision 44 — dégradé, mais jamais nul.
func (proc *Executor) closeSegmentAtFreeze(meter *stepMeter, traceID, pauseID string) bool {
	energyUJ, cpu, err := proc.segmentSnapshot()
	if err != nil || cpu.ProcessTicks < meter.segCPU.ProcessTicks {
		logSegmentMarkMissing("freeze", traceID, pauseID, err)
		return false
	}
	meter.closeAt(energyUJ, cpu)
	proc.marks.noteFreeze(energyUJ, cpu)
	return true
}

// openSegmentAtResume : à appeler une fois la reprise effective. Ouvre un
// nouveau segment et complète la marque. Rend le temps CPU consommé par le
// conteneur pendant le gel (le contrôle du gel : il doit être nul) ; ok vaut
// false si rien n'a pu être mesuré.
//
// Si le relevé de reprise est inutilisable, le segment repart des valeurs du
// gel avec l'heure présente : l'énergie du nœud pendant le gel entre alors
// dans le segment suivant. C'est une surestimation, jamais une perte.
func (proc *Executor) openSegmentAtResume(meter *stepMeter, traceID, pauseID string) (cpuUsecWhileFrozen int64, ok bool) {
	if !meter.frozen {
		return 0, false
	}
	energyUJ, cpu, err := proc.segmentSnapshot()
	if err != nil || cpu.ProcessTicks < meter.frozenCPU.ProcessTicks {
		logSegmentMarkMissing("resume", traceID, pauseID, err)
		energyUJ = meter.frozenEnergy
		cpu = CPUSnapshot{ProcessTicks: meter.frozenCPU.ProcessTicks, WallNs: time.Now().UnixNano()}
		meter.openAt(energyUJ, cpu)
		proc.marks.noteResume(energyUJ, cpu)
		return 0, false
	}
	cpuUsecWhileFrozen = cpu.ProcessTicks - meter.frozenCPU.ProcessTicks
	meter.openAt(energyUJ, cpu)
	proc.marks.noteResume(energyUJ, cpu)
	return cpuUsecWhileFrozen, true
}

// logSegmentMarkMissing : §11, aucun repli implicite. Un relevé de gel ou de
// reprise inutilisable est rare (le compteur d'énergie était lisible à
// l'instant d'avant) ; chaque occurrence dégrade la mesure d'un cycle.
func logSegmentMarkMissing(at, traceID, pauseID string, err error) {
	fields := map[string]interface{}{
		"event":    "ENERGY_SEGMENT_MARK_MISSING",
		"at":       at,
		"trace_id": traceID,
		"pause_id": pauseID,
		"detail": "relevé d'énergie ou de temps CPU inutilisable à cette frontière de segment : " +
			"gel → ce cycle est mesuré d'un seul tenant ; reprise → le segment suivant repart des valeurs du gel",
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	encoded, mErr := json.Marshal(fields)
	if mErr != nil {
		log.Printf("[safety] ENERGY_SEGMENT_MARK_MISSING at=%s trace=%s pause=%s", at, traceID, pauseID)
		return
	}
	log.Printf("[safety] %s", encoded)
}
