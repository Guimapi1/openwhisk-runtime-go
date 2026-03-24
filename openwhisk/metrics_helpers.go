package openwhisk

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// CPUSnapshot contient les ticks CPU d'un processus et du nœud entier,
// lus quasi-simultanément pour minimiser le biais temporel.
// IdleTicks est la somme des ticks idle des cores du socket mesuré.
type CPUSnapshot struct {
	ProcessTicks int64 // utime + stime de tous les threads du pid cible
	TotalTicks   int64 // somme de tous les ticks des cores du socket (idle inclus)
	IdleTicks    int64 // somme des ticks idle des cores du socket
	WallNs       int64 // timestamp wall-clock en nanosecondes (time.Now().UnixNano())
}

// readEnergy lit la valeur RAPL courante en microjoules depuis le chemin configuré.
func readEnergy() (int64, error) {
	raplPath := os.Getenv("RAPL_PATH")
	if raplPath == "" {
		raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:1/energy_uj"
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
		raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:1/energy_uj"
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

// deltaRAPLUJ calcule la consommation énergétique entre deux relevés en µJ,
// en corrigeant l'éventuel overflow du registre RAPL.
func deltaRAPLUJ(start, end int64) int64 {
	if end >= start {
		return end - start
	}
	max := readRAPLMax()
	return (max - start) + end
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

// readProcessTicks lit utime+stime du processus pid ET de tous ses threads
// depuis /proc/<pid>/task/*/stat, puis additionne tout.
// Les processus enfants (subprocess) sont capturés via cutime+cstime dans
// /proc/<pid>/stat une fois terminés.
func readProcessTicks(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}

	// Lire les ticks du processus principal + cutime/cstime (enfants terminés)
	mainData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("readProcessTicks pid=%d: %v", pid, err)
	}
	mainTicks, err := readStatTicksWithChildren(mainData)
	if err != nil {
		return 0, err
	}

	// Ajouter les ticks des threads vivants depuis /proc/<pid>/task/*/stat
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return mainTicks, nil
	}

	var threadTicks int64
	for _, entry := range entries {
		// Ignorer le thread principal déjà compté
		if entry.Name() == fmt.Sprintf("%d", pid) {
			continue
		}
		statPath := fmt.Sprintf("%s/%s/stat", taskDir, entry.Name())
		data, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}
		ticks, err := readStatTicks(data)
		if err != nil {
			continue
		}
		threadTicks += ticks
	}

	return mainTicks + threadTicks, nil
}

// readStatTicksWithChildren extrait utime+stime+cutime+cstime depuis /proc/<pid>/stat.
// cutime et cstime accumulent les ticks des processus enfants terminés (ex: espeak, ffmpeg).
func readStatTicksWithChildren(data []byte) (int64, error) {
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return 0, fmt.Errorf("unexpected stat format")
	}
	// Après ')' : state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
	// flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10)
	// utime(11) stime(12) cutime(13) cstime(14)
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) < 15 {
		return 0, fmt.Errorf("not enough fields for children ticks")
	}
	var total int64
	for _, idx := range []int{11, 12, 13, 14} {
		v, err := strconv.ParseInt(fields[idx], 10, 64)
		if err != nil {
			return 0, err
		}
		total += v
	}
	return total, nil
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

// socketTicks contient la décomposition des ticks d'un socket en actifs et idle.
type socketTicks struct {
	Total int64
	Idle  int64
}

// readSocketTicks lit les ticks total et idle des cores du socket depuis /proc/stat.
// Si RAPL_CORES est défini, on filtre sur ces cores. Sinon on utilise la ligne "cpu ".
func readSocketTicks() (socketTicks, error) {
	coreMask := os.Getenv("RAPL_CORES")

	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return socketTicks{}, err
	}

	// Sans filtre : ligne agrégée "cpu "
	// Format : cpu user nice system idle iowait irq softirq steal guest guest_nice
	//          [0]  [1]  [2]   [3]    [4]   [5]   [6]  [7]     [8]   [9]   [10]
	// idle = fields[4], iowait = fields[5] (inclus dans idle pour Kepler)
	if coreMask == "" {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				return socketTicks{}, fmt.Errorf("/proc/stat: cpu line too short")
			}
			var st socketTicks
			for _, f := range fields[1:] {
				v, err := strconv.ParseInt(f, 10, 64)
				if err == nil {
					st.Total += v
				}
			}
			// idle (index 4 dans fields[1:] = fields[4]) + iowait (index 5 = fields[5])
			idle, _ := strconv.ParseInt(fields[4], 10, 64)
			iowait, _ := strconv.ParseInt(fields[5], 10, 64)
			st.Idle = idle + iowait
			return st, nil
		}
		return socketTicks{}, fmt.Errorf("/proc/stat: cpu line not found")
	}

	// Avec filtre : sommer uniquement les cores du socket cible
	allowedCores := parseCoreMask(coreMask)
	var st socketTicks
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		coreID, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu"))
		if err != nil || !allowedCores[coreID] {
			continue
		}
		for _, f := range fields[1:] {
			v, err := strconv.ParseInt(f, 10, 64)
			if err == nil {
				st.Total += v
			}
		}
		idle, _ := strconv.ParseInt(fields[4], 10, 64)
		iowait, _ := strconv.ParseInt(fields[5], 10, 64)
		st.Idle += idle + iowait
		found = true
	}
	if !found {
		return socketTicks{}, fmt.Errorf("/proc/stat: no matching cores for mask %q", coreMask)
	}
	return st, nil
}

// readCPUSnapshot lit simultanément les ticks du processus, du socket et le wall-clock.
func readCPUSnapshot(pid int) CPUSnapshot {
	snap := CPUSnapshot{WallNs: time.Now().UnixNano()}

	var err error
	snap.ProcessTicks, err = readProcessTicks(pid)
	if err != nil {
		log.Printf("readCPUSnapshot pid=%d: %v", pid, err)
	}

	st, err := readSocketTicks()
	if err != nil {
		log.Printf("readCPUSnapshot socket ticks: %v", err)
	} else {
		snap.TotalTicks = st.Total
		snap.IdleTicks = st.Idle
	}
	return snap
}

// attributedEnergyUJ calcule l'énergie attribuée à l'action en µJ.
//
// On adopte la même décomposition que Kepler :
//
//	énergie_active  = delta_RAPL × (1 - ratio_idle_socket)
//	énergie_idle    = delta_RAPL × ratio_idle_socket
//
//	attribution = énergie_active × (process_ticks / non_idle_ticks_socket)
//	            + énergie_idle   × (durée_action_ns / durée_fenêtre_ns)
//
// La composante idle capture l'énergie consommée pendant les attentes I/O
// (appels réseau, accès fichiers) proportionnellement au temps d'occupation.
func attributedEnergyUJ(energyStart, energyEnd int64, snapStart, snapEnd CPUSnapshot) int64 {
	deltaRAPL := deltaRAPLUJ(energyStart, energyEnd)
	if deltaRAPL <= 0 {
		return 0
	}

	deltaTotal := snapEnd.TotalTicks - snapStart.TotalTicks
	deltaIdle := snapEnd.IdleTicks - snapStart.IdleTicks
	deltaProcess := snapEnd.ProcessTicks - snapStart.ProcessTicks
	durationNs := snapEnd.WallNs - snapStart.WallNs
	windowNs := durationNs // fenêtre = durée de l'action

	if deltaTotal <= 0 || windowNs <= 0 {
		return 0
	}

	// Ratio idle du socket pendant la fenêtre
	// deltaNonIdle = ticks actifs (user+system+irq...) hors idle/iowait
	deltaNonIdle := deltaTotal - deltaIdle
	if deltaNonIdle < 0 {
		deltaNonIdle = 0
	}

	// Énergie active et idle du socket
	ratioIdle := float64(deltaIdle) / float64(deltaTotal)
	energyActiveUJ := float64(deltaRAPL) * (1.0 - ratioIdle)
	energyIdleUJ := float64(deltaRAPL) * ratioIdle

	// Part active : pondération par les ticks CPU du processus
	var activeAttribUJ float64
	if deltaNonIdle > 0 && deltaProcess > 0 {
		cpuRatio := float64(deltaProcess) / float64(deltaNonIdle)
		if cpuRatio > 1.0 {
			cpuRatio = 1.0
		}
		activeAttribUJ = energyActiveUJ * cpuRatio
	}

	// Part idle : pondération par le temps d'occupation (wall-clock)
	// windowNs = durée de l'action, on utilise le même windowNs comme référence
	// car on n'a qu'une seule action dans cette fenêtre de mesure.
	// On attribue donc 100% de l'idle du socket à cette action sur cette fenêtre.
	idleAttribUJ := energyIdleUJ

	total := int64(activeAttribUJ + idleAttribUJ)
	log.Printf("attributedEnergyUJ: deltaRAPL=%dµJ active=%.0fµJ idle=%.0fµJ => attributed=%dµJ (cpuRatio=%.4f idleRatio=%.4f)",
		deltaRAPL, activeAttribUJ, idleAttribUJ, total,
		float64(deltaProcess)/float64(max64(deltaNonIdle, 1)),
		ratioIdle)
	return total
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// recordMetrics calcule et enregistre les métriques énergétiques d'un endpoint.
func (ap *ActionProxy) recordMetrics(endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta) {
	energyEnd, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy end %s: %v", endpoint, err)
	}
	end := time.Now().UnixNano()

	var cpuEnd CPUSnapshot
	if ap.theExecutor != nil {
		cpuEnd = readCPUSnapshot(ap.theExecutor.Pid())
	}
	// Corriger le WallNs de fin avec le timestamp déjà lu
	cpuEnd.WallNs = end

	attributed := attributedEnergyUJ(energyStart, energyEnd, cpuStart, cpuEnd)

	entry := Entry{
		Start:            start,
		End:              end,
		EnergyStart:      energyStart,
		EnergyEnd:        energyEnd,
		EnergyAttributed: attributed,
	}
	if meta != nil {
		entry.TraceID      = meta.TraceID
		entry.PodName      = meta.PodName
		entry.ActivationID = meta.ActivationID
	}

	if ap.metrics != nil {
		ap.metrics.Add(endpoint, entry)
	}

	if endpoint == "/run" {
		ap.pendingInitMu.Lock()
		if ap.pendingInitEntry != nil {
			ap.pendingInitEntry.TraceID      = entry.TraceID
			ap.pendingInitEntry.ActivationID = entry.ActivationID
			pending := *ap.pendingInitEntry
			ap.pendingInitEntry = nil
			ap.pendingInitMu.Unlock()
			go pushMetrics("/init", pending)
		} else {
			ap.pendingInitMu.Unlock()
		}
		go pushMetrics("/run", entry)
	} else {
		ap.pendingInitMu.Lock()
		ap.pendingInitEntry = &entry
		ap.pendingInitMu.Unlock()
	}
}