package openwhisk

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// CPUSnapshot contient les mesures CPU prises quasi-simultanément.
//
// ProcessTicks : microsecondes de CPU consommées par le container (cgroup
//   usage_usec), tous processus et threads confondus (Python, espeak, ffmpeg...).
// WallNs : timestamp wall-clock en ns, utilisé pour calculer la capacité
//   théorique du socket sur la fenêtre de mesure.
type CPUSnapshot struct {
	ProcessTicks int64 // CPU du container en µs (cgroup usage_usec)
	WallNs       int64 // timestamp wall-clock en ns
}

// readEnergy lit la valeur RAPL courante en microjoules depuis le chemin configuré.
func readEnergy() (int64, error) {
	raplPath := os.Getenv("RAPL_PATH")
	if raplPath == "" {
		raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"
	}
	dat, err := os.ReadFile(raplPath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(dat)), 10, 64)
}

// raplMaxDir déduit le répertoire RAPL depuis RAPL_PATH.
func raplMaxDir() string {
	raplPath := os.Getenv("RAPL_PATH")
	if raplPath == "" {
		raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"
	}
	return raplPath[:strings.LastIndex(raplPath, "/")]
}

// readRAPLMax lit la valeur maximale du registre RAPL en µJ.
// En cas d'erreur, retourne 2^32 µJ (~4.29 kJ).
func readRAPLMax() int64 {
	path := raplMaxDir() + "/max_energy_range_uj"
	dat, err := os.ReadFile(path)
	if err != nil {
		log.Printf("readRAPLMax: %v — using default 2^32", err)
		return 1 << 32
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(dat)), 10, 64)
	if err != nil || v <= 0 {
		log.Printf("readRAPLMax: invalid value — using default 2^32")
		return 1 << 32
	}
	return v
}

// raplOverflowProximityThreshold (env RAPL_OVERFLOW_PROXIMITY_THRESHOLD,
// défaut 0.9) : fraction de max_energy_range_uj au-delà de laquelle
// `start` est considéré assez proche du sommet du compteur pour qu'un
// `end < start` soit plausiblement un vrai débordement matériel plutôt
// qu'une simple fluctuation de lecture. Un vrai débordement ne peut se
// produire qu'en repassant par ce sommet — jamais depuis une valeur
// arbitraire (voir deltaRAPLUJ ci-dessous). 0.9 est un choix
// conservateur documenté, pas calibré expérimentalement (même statut
// que les autres marges de ce fichier, §8) : suffisamment haut pour
// qu'aucune consommation réelle plausible sur une seule fenêtre de
// mesure ne l'atteigne par hasard, suffisamment bas pour couvrir la
// marge d'imprécision du compteur lui-même.
func raplOverflowProximityThreshold() float64 {
	if v := os.Getenv("RAPL_OVERFLOW_PROXIMITY_THRESHOLD"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 && parsed <= 1.0 {
			return parsed
		}
	}
	return 0.9
}

// logNonMonotonicRAPLReading (CLAUDE.md §11 : aucun fallback implicite,
// toute décision visible dans l'état et les logs) — un incident
// [safety] de premier ordre, distinct de tout autre log de ce fichier :
// une lecture RAPL non strictement monotone qui n'a PAS la signature
// d'un vrai débordement (start loin du sommet du compteur) est une
// instabilité de lecture matérielle/noyau réelle, pas un événement
// routinier — elle ne doit plus jamais rester silencieuse, même une
// fois ce correctif en place, car c'est un indicateur direct pour
// l'évaluation expérimentale de la fiabilité de la mesure elle-même
// (même statut que les incidents NON_INTERRUPTIBLE/RECOVERY_BUDGET_
// EXHAUSTED/franchissement de créneau, §11 dernier point).
func logNonMonotonicRAPLReading(start, end, max, threshold int64) {
	encoded, err := json.Marshal(map[string]interface{}{
		"event":        "RAPL_NON_MONOTONIC_READING",
		"start_uj":     start,
		"end_uj":       end,
		"max_uj":       max,
		"threshold_uj": threshold,
		"detail": "end < start but start was not near max_energy_range_uj -- " +
			"treated as an unreliable reading, not a register overflow; " +
			"this tick's delta is 0, not corrected via wraparound",
	})
	if err != nil {
		log.Printf(
			"[safety] RAPL non-monotonic reading start=%d end=%d (failed to marshal structured event: %v)",
			start, end, err,
		)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// logEnergyAttributionFallbackUsed (CLAUDE.md §11: aucun fallback
// implicite) — logged every time recordMetricsImpl's defense-in-depth
// safety net actually fires (a genuinely zero final CPU-ratio attribution
// substituted by the live, pre-kill EnergyKillInfo.EnergyConsumedJ). This
// is meant to stay rare after the ordering/cgroup-path fix — every
// occurrence signals that the primary mechanism did not behave as
// expected and deserves investigation, not silent absorption.
func logEnergyAttributionFallbackUsed(meta *RunMeta, zeroAttributedUJ int64, fallbackJ float64) {
	fields := map[string]interface{}{
		"event":              "ENERGY_ATTRIBUTION_FALLBACK_USED",
		"attributed_uj":      zeroAttributedUJ,
		"fallback_j":         fallbackJ,
		"detail": "final CPU-ratio attribution computed as 0 despite the " +
			"ordering/cgroup-path fix -- substituted with the value already " +
			"measured live, before the kill, by monitorEnergy()'s own ticker",
	}
	if meta != nil {
		fields["trace_id"] = meta.TraceID
		fields["activation_id"] = meta.ActivationID
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		log.Printf(
			"[safety] energy attribution fallback used, fallback_j=%.4f (failed to marshal structured event: %v)",
			fallbackJ, err,
		)
		return
	}
	log.Printf("[safety] %s", encoded)
}

// deltaRAPLUJ calcule la consommation énergétique entre deux relevés en µJ,
// en corrigeant l'éventuel overflow du registre RAPL.
//
// Un vrai débordement matériel ne peut se produire qu'en repassant par
// le sommet du compteur (max_energy_range_uj) — `end < start` seul ne
// le prouve pas : une lecture RAPL non strictement monotone (un
// "recul" de quelques dizaines à centaines de µJ entre deux lectures)
// est une instabilité de lecture réelle et documentée du matériel/
// noyau, pas un débordement. Un incident réel trouvé sur cluster (§0 —
// voir le journal des décisions) : sans cette double condition,
// n'importe quelle fluctuation triviale de ce type injectait
// silencieusement toute la plage max_energy_range_uj (couramment
// plusieurs dizaines à centaines de kJ) dans le delta calculé — un
// delta d'environ 2875-2884J mesuré à partir d'une consommation réelle
// de l'ordre de quelques dizaines de joules.
func deltaRAPLUJ(start, end int64) int64 {
	if end >= start {
		return end - start
	}
	max := readRAPLMax()
	threshold := int64(float64(max) * raplOverflowProximityThreshold())
	if start >= threshold {
		// Signature d'un vrai débordement : start était déjà proche du
		// sommet du compteur, un retour en arrière est physiquement
		// attendu dans ce cas précis.
		return (max - start) + end
	}
	// end < start mais start était loin de max_energy_range_uj : une
	// lecture non monotone, pas un vrai débordement. La traiter comme
	// un débordement injecterait toute la plage max à partir d'une
	// simple fluctuation (l'incident réel que ce correctif prévient).
	//
	// Choix explicite (documenté, pas une troisième option inventée) :
	// ce tick est traité comme delta=0, cohérent avec tous les autres
	// cas de données insuffisantes/non fiables que cette fonction
	// traite déjà ainsi (deltaProcessUsec<=0, durationUsec<=0 dans
	// attributedEnergyUJ ci-dessous) — plutôt que de fabriquer un
	// nombre négatif, ou de faire persister silencieusement un
	// rebasage de `start` à travers des appels ultérieurs, ce que
	// cette fonction pure ne possède pas les moyens de faire sans
	// muter un état partagé qu'elle ne détient pas.
	logNonMonotonicRAPLReading(start, end, max, threshold)
	return 0
}

// readStatTicks extrait utime+stime depuis le contenu d'un fichier /proc/*/stat.
func readStatTicks(data []byte) (int64, error) {
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return 0, fmt.Errorf("unexpected stat format")
	}
	// Après ')' : state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
	// flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("not enough fields")
	}
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}

// readProcessTicks lit les ticks CPU du container via le cgroup du processus pid.
//
// On lit /proc/<pid>/cgroup pour trouver le cgroup du container, puis
// cpu.stat dans ce cgroup. Ce fichier cumule les ticks de TOUS les processus
// et threads qui ont tourné dans le container (y compris espeak, ffmpeg et
// leurs threads), sans avoir à les tracker individuellement.
//
// Deux hiérarchies sont supportées :
//   - cgroups v2 : /sys/fs/cgroup/<slice>/cpu.stat  (champ usage_usec)
//   - cgroups v1 : /sys/fs/cgroup/cpuacct/<slice>/cpuacct.usage (en ns)
//
// On retourne une valeur en microsecondes pour rester cohérent avec USER_HZ.
func readProcessTicks(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}

	// Lire le cgroup du processus
	cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, fmt.Errorf("read cgroup for pid %d: %v", pid, err)
	}

	// Essayer cgroups v2 d'abord (ligne "0::/...")
	for _, line := range strings.Split(string(cgroupData), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		slice := strings.TrimPrefix(line, "0::/")
		slice = strings.TrimSpace(slice)
		cpuStatPath := "/sys/fs/cgroup/" + slice + "/cpu.stat"
		usec, err := readCgroupV2CPUUsec(cpuStatPath)
		if err == nil {
			return usec, nil
		}
	}

	// Fallback cgroups v1 (ligne "7::cpuacct:/...")
	for _, line := range strings.Split(string(cgroupData), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[1] != "cpuacct" && !strings.Contains(fields[1], "cpuacct") {
			continue
		}
		slice := strings.TrimSpace(fields[2])
		cpuacctPath := "/sys/fs/cgroup/cpuacct/" + slice + "/cpuacct.usage"
		dat, err := os.ReadFile(cpuacctPath)
		if err != nil {
			continue
		}
		ns, err := strconv.ParseInt(strings.TrimSpace(string(dat)), 10, 64)
		if err != nil {
			continue
		}
		return ns / 1000, nil // ns → µs
	}

	return 0, fmt.Errorf("no cgroup cpu usage found for pid %d", pid)
}

// ResolveCgroupCPUStatPath is diagnostic-only tooling (CLAUDE.md §7.3
// investigation, cmd/verify_cgroup_pod): mirrors readProcessTicks()'s own
// cgroups-v2-then-v1 resolution to report WHICH FILE it would read for
// pid, without touching readProcessTicks() itself while that function's
// behaviour is under active investigation — the production code path
// above is deliberately left untouched. Necessarily a duplicate of that
// resolution logic, not a shared helper; if the two ever drift, this
// comment is the tripwire to keep them in sync by hand.
func ResolveCgroupCPUStatPath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}

	cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read cgroup for pid %d: %v", pid, err)
	}

	for _, line := range strings.Split(string(cgroupData), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		slice := strings.TrimPrefix(line, "0::/")
		slice = strings.TrimSpace(slice)
		cpuStatPath := "/sys/fs/cgroup/" + slice + "/cpu.stat"
		if _, err := readCgroupV2CPUUsec(cpuStatPath); err == nil {
			return cpuStatPath, nil
		}
	}

	for _, line := range strings.Split(string(cgroupData), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[1] != "cpuacct" && !strings.Contains(fields[1], "cpuacct") {
			continue
		}
		slice := strings.TrimSpace(fields[2])
		cpuacctPath := "/sys/fs/cgroup/cpuacct/" + slice + "/cpuacct.usage"
		if _, err := os.ReadFile(cpuacctPath); err == nil {
			return cpuacctPath, nil
		}
	}

	return "", fmt.Errorf("no cgroup cpu usage file found for pid %d", pid)
}

// readCgroupV2CPUUsec lit usage_usec depuis un fichier cpu.stat cgroups v2.
func readCgroupV2CPUUsec(path string) (int64, error) {
	dat, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(dat), "\n") {
		if !strings.HasPrefix(line, "usage_usec ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		return strconv.ParseInt(fields[1], 10, 64)
	}
	return 0, fmt.Errorf("usage_usec not found in %s", path)
}

// parseCoreMask parse une liste de ranges de cores comme "26-51,78-103"
// et retourne un set de core IDs.
func parseCoreMask(mask string) map[int]bool {
	cores := make(map[int]bool)
	if mask == "" {
		return cores
	}
	for _, part := range strings.Split(mask, ",") {
		part = strings.TrimSpace(part)
		bounds := strings.Split(part, "-")
		if len(bounds) == 1 {
			id, err := strconv.Atoi(bounds[0])
			if err == nil {
				cores[id] = true
			}
		} else if len(bounds) == 2 {
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 == nil && err2 == nil {
				for i := lo; i <= hi; i++ {
					cores[i] = true
				}
			}
		}
	}
	return cores
}


// readCPUSnapshot lit le CPU cgroup du container et le wall-clock simultanément.
func readCPUSnapshot(pid int) CPUSnapshot {
	snap := CPUSnapshot{WallNs: time.Now().UnixNano()}

	var err error
	snap.ProcessTicks, err = readProcessTicks(pid)
	if err != nil {
		log.Printf("readCPUSnapshot pid=%d: %v", pid, err)
	}
	return snap
}

// readCPUSnapshotFromCgroup is readCPUSnapshot's PID-independent
// counterpart, reading cpu.stat directly from an already-known cgroup
// path rather than discovering it via /proc/{pid}/cgroup.
//
// Necessary for any snapshot taken AFTER killExecution() has run:
// killExecution() (cgroupFreezer.go) calls cmd.Wait() internally as part
// of confirming the kill, which fully reaps the process before
// killExecution() ever returns — by the time control reaches this
// snapshot, /proc/{pid} is already gone (not merely a zombie), so
// readProcessTicks(pid)'s own /proc/{pid}/cgroup lookup would fail and
// silently report 0. The activation's own cgroup directory persists
// independently of that PID's lifetime (removed only later, by
// Executor.Stop()/ActivationController.Close() — a separate, later
// lifecycle event, CLAUDE.md §7.3), and cpu.stat's usage_usec is a
// cgroup-wide, monotonic counter that does not depend on which task
// within it is still alive.
//
// Real incident this fixes: a killed activation with substantial real
// CPU work beforehand (confirmed independently via the live,
// pre-kill EnergyKillInfo.EnergyConsumedJ) still reported
// energy_attributed_uj=0 to the collector, because the PID-based final
// snapshot always failed post-reap — silently, not a rare edge case,
// unconditional for every kill.
func readCPUSnapshotFromCgroup(cgroupPath string) CPUSnapshot {
	snap := CPUSnapshot{WallNs: time.Now().UnixNano()}
	if cgroupPath == "" {
		return snap
	}

	usec, err := readCgroupV2CPUUsec(cgroupPath + "/cpu.stat")
	if err != nil {
		log.Printf("readCPUSnapshotFromCgroup path=%s: %v", cgroupPath, err)
		return snap
	}
	snap.ProcessTicks = usec
	return snap
}

// attributedEnergyUJ calcule l'énergie attribuée à l'action en µJ.
//
// Formule :
//
//	capacité_socket_usec = durée_wall_ns / 1000 × nb_cores_socket
//	attribution = delta_RAPL × (process_usec / capacité_socket_usec)
//
// On divise par la capacité théorique maximale du socket (wall-clock × cores)
// plutôt que par les ticks non-idle observés. Cela évite l'explosion du ratio
// quand le socket est quasi-idle (cas typique d'un socket dédié aux actions).
// C'est la même logique que Kepler.
//
// ProcessTicks est en µs (cgroup usage_usec) — il inclut tous les processus
// et threads du container (Python, espeak, ffmpeg...).
// Le nombre de cores du socket est lu depuis RAPL_CORES (ex: "26-51,78-103").
// Si RAPL_CORES n'est pas défini, on utilise le nombre total de cores logiques.
//
// Retourne 0 si les données sont insuffisantes.
func attributedEnergyUJ(energyStart, energyEnd int64, snapStart, snapEnd CPUSnapshot) int64 {
	deltaRAPL := deltaRAPLUJ(energyStart, energyEnd)
	if deltaRAPL <= 0 {
		return 0
	}

	deltaProcessUsec := snapEnd.ProcessTicks - snapStart.ProcessTicks
	if deltaProcessUsec <= 0 {
		return 0
	}

	// Durée wall-clock de l'invocation en µs
	durationUsec := (snapEnd.WallNs - snapStart.WallNs) / 1000
	if durationUsec <= 0 {
		return 0
	}

	// Nombre de cores du socket mesuré
	nbCores := int64(countCores(os.Getenv("RAPL_CORES")))
	if nbCores <= 0 {
		nbCores = int64(countAllCores())
	}

	// Capacité totale du socket sur la fenêtre de mesure
	capacityUsec := durationUsec * nbCores

	cpuRatio := float64(deltaProcessUsec) / float64(capacityUsec)
	if cpuRatio > 1.0 {
		cpuRatio = 1.0
	}

	attributed := int64(float64(deltaRAPL) * cpuRatio)

	log.Printf("attributedEnergyUJ: deltaRAPL=%dµJ processUsec=%d capacityUsec=%d nbCores=%d cpuRatio=%.4f => attributed=%dµJ",
		deltaRAPL, deltaProcessUsec, capacityUsec, nbCores, cpuRatio, attributed)

	return attributed
}

// countCores compte le nombre de cores dans un masque RAPL_CORES.
// Ex: "26-51,78-103" → 52 cores.
func countCores(mask string) int {
	if mask == "" {
		return 0
	}
	return len(parseCoreMask(mask))
}

// countAllCores compte le nombre de cores logiques depuis /proc/stat.
func countAllCores() int {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 1
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu") && !strings.HasPrefix(line, "cpu ") {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}


// recordMetrics calcule et enregistre les métriques énergétiques d'un
// endpoint, en poussant vers le collecteur de façon fire-and-forget (goroutine
// séparée) — le comportement historique, correct partout où rien n'attend
// synchroniquement que l'écriture soit effective avant de continuer.
func (ap *ActionProxy) recordMetrics(endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta) {
	ap.recordMetricsImpl(endpoint, start, energyStart, cpuStart, meta, false, 0)
}

// recordMetricsSync est identique à recordMetrics, mais pousse la mesure de
// CETTE activation vers le collecteur de façon SYNCHRONE (bloquante) plutôt
// que via une goroutine fire-and-forget.
//
// Nécessaire précisément avant l'envoi de EXECUTION_KILLED (CLAUDE.md §6.9,
// passe de durcissement, point 2) : postExecutionKilled() est elle-même
// fire-and-forget côté runtime (aucune confirmation attendue avant l'envoi,
// confirmé phases 6/7), et le scheduler interroge
// collector.get_energy_for_trace(trace_id) dès réception de cet événement.
// Avec recordMetrics() ordinaire, rien ne garantit que l'écriture de CETTE
// mesure ait atteint le collecteur avant que le scheduler ne l'interroge —
// deux fire-and-forget indépendants (le push metrics ET l'envoi de
// l'événement) sans aucune synchronisation entre eux, donc une vraie
// fenêtre de course, pas juste une possibilité théorique. recordMetricsSync
// doit être appelée AVANT le déclenchement de postExecutionKilled(), jamais
// après (voir runHandler.go, branche killInfo != nil) — ET avant que
// ap.theExecutor ne soit mis à nil dans cette même branche (voir
// recordMetricsSyncWithFallback ci-dessous : le calcul final a besoin que
// l'executor soit encore accessible, pas que le process soit encore vivant).
func (ap *ActionProxy) recordMetricsSync(endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta) {
	ap.recordMetricsImpl(endpoint, start, energyStart, cpuStart, meta, true, 0)
}

// recordMetricsSyncWithFallback est identique à recordMetricsSync, avec un
// filet de sécurité en plus : fallbackJ (CLAUDE.md §6.9, garde-fou de
// défense en profondeur, PAS le mécanisme principal — voir readCPUSnapshotFromCgroup
// et l'ordonnancement dans runHandler.go pour le vrai correctif). Si cette
// activation calcule malgré tout une attribution CPU strictement nulle
// (attributed == 0) au règlement, ce n'est substitué QUE dans ce cas précis
// par fallbackJ — une valeur déjà calculée EN DIRECT, avant le kill, par le
// propre ticker de monitorEnergy() (EnergyKillInfo.EnergyConsumedJ), donc
// jamais soumise au problème de PID déjà fauché qui affecte le relevé final.
// N'est appelée que depuis la branche killInfo != nil de runHandler.go —
// jamais depuis le chemin de complétion normale (fallbackJ vaudrait 0 là,
// donc n'aurait de toute façon aucun effet, mais ce chemin n'a même pas de
// valeur de repli à offrir).
func (ap *ActionProxy) recordMetricsSyncWithFallback(
	endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta, fallbackJ float64,
) {
	ap.recordMetricsImpl(endpoint, start, energyStart, cpuStart, meta, true, fallbackJ)
}

func (ap *ActionProxy) recordMetricsImpl(
	endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta, sync bool, fallbackJ float64,
) {
	energyEnd, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy end %s: %v", endpoint, err)
	}
	end := time.Now().UnixNano()

	// readCPUSnapshotFromCgroup, not readCPUSnapshot(pid): by the time this
	// runs after a kill, killExecution()'s own internal cmd.Wait() has
	// already fully reaped the process (cgroupFreezer.go) — /proc/{pid} is
	// gone, not merely a zombie. The activation's cgroup directory itself
	// persists independently of that PID (removed later, by
	// Executor.Stop()/ActivationController.Close()), so reading cpu.stat
	// via the known cgroup path works whether the process is still running
	// (normal completion) or already reaped (kill path) — a single,
	// PID-independent mechanism for both.
	var cpuEnd CPUSnapshot
	if ap.theExecutor != nil {
		cpuEnd = readCPUSnapshotFromCgroup(ap.theExecutor.CgroupPath())
	}
	// Corriger le WallNs de fin avec le timestamp déjà lu
	cpuEnd.WallNs = end

	attributed := attributedEnergyUJ(energyStart, energyEnd, cpuStart, cpuEnd)

	// Defense-in-depth safety net (CLAUDE.md §6.9), not the primary fix:
	// the ordering (recordMetricsSync called before ap.theExecutor = nil,
	// runHandler.go) plus readCPUSnapshotFromCgroup above should already
	// make attributed == 0 mean "genuinely zero CPU work", never "could not
	// measure". This substitution exists only in case that assumption ever
	// breaks again (a future regression, or the cgroup already removed by
	// the time this runs) — real incident this replaces: a killed
	// activation with substantial real CPU work still silently reported
	// energy_attributed_uj=0 because the final snapshot's PID had already
	// been reaped. fallbackJ is 0 (a no-op here) on every call site except
	// recordMetricsSyncWithFallback's own kill-path caller.
	if attributed == 0 && fallbackJ > 0 {
		logEnergyAttributionFallbackUsed(meta, attributed, fallbackJ)
		attributed = int64(fallbackJ * 1e6)
	}

	entry := Entry{
		Start:            start,
		End:              end,
		EnergyStart:      energyStart,
		EnergyEnd:        energyEnd,
		EnergyAttributed: attributed,
	}
	if meta != nil {
		entry.TraceID        = meta.TraceID
		entry.PodName        = meta.PodName
		entry.ActivationID   = meta.ActivationID
		entry.ExecutionPhase = meta.ExecutionPhase
	}

	if ap.metrics != nil {
		ap.metrics.Add(endpoint, entry)
	}

	if endpoint == "/run" {
		ap.pendingInitMu.Lock()
		if ap.pendingInitEntry != nil {
			ap.pendingInitEntry.TraceID      = entry.TraceID
			ap.pendingInitEntry.ActivationID = entry.ActivationID
			// D4 (§6.10): the /init point belongs to the same invocation
			// as this /run, so it must carry the same phase. Left
			// untagged it would default to "forward" at read time and a
			// compensation container's init energy would leak into the
			// forward reference — the very contamination D4 removes.
			ap.pendingInitEntry.ExecutionPhase = entry.ExecutionPhase
			pending := *ap.pendingInitEntry
			ap.pendingInitEntry = nil
			ap.pendingInitMu.Unlock()
			if sync {
				pushMetrics("/init", pending)
			} else {
				go pushMetrics("/init", pending)
			}
		} else {
			ap.pendingInitMu.Unlock()
		}
		if sync {
			pushMetrics("/run", entry)
		} else {
			go pushMetrics("/run", entry)
		}
	} else {
		ap.pendingInitMu.Lock()
		ap.pendingInitEntry = &entry
		ap.pendingInitMu.Unlock()
	}
}