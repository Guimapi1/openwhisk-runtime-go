package openwhisk

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// CPUSnapshot contient les mesures CPU prises quasi-simultanément.
//
// ProcessTicks : microsecondes de CPU consommées par le container (cgroup),
//   tous processus et threads confondus. Unité : µs.
// TotalTicks, IdleTicks : ticks USER_HZ des cores du socket mesuré (RAPL_CORES).
//   Convertis en µs dans attributedEnergyUJ (1 tick = 10000µs à USER_HZ=100).
// WallNs : timestamp wall-clock pour mesurer la durée réelle de l'action.
type CPUSnapshot struct {
	ProcessTicks int64 // CPU du container en µs (cgroup usage_usec)
	TotalTicks   int64 // ticks USER_HZ totaux des cores du socket
	IdleTicks    int64 // ticks USER_HZ idle+iowait des cores du socket
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
// Le dénominateur (socketTicks) est lui aussi converti en µs dans attributedEnergyUJ.
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
// Formule :
//
//	attribution = delta_RAPL × (process_usec / non_idle_usec_socket)
//
// ProcessTicks (issu du cgroup) est en microsecondes de CPU consommées par
// tous les processus du container (Python + espeak + ffmpeg + threads).
// TotalTicks et IdleTicks sont en ticks USER_HZ — on les convertit en µs
// en divisant par USER_HZ (100) et en multipliant par 1e6.
//
// Retourne 0 si les données sont insuffisantes.
func attributedEnergyUJ(energyStart, energyEnd int64, snapStart, snapEnd CPUSnapshot) int64 {
	deltaRAPL := deltaRAPLUJ(energyStart, energyEnd)
	if deltaRAPL <= 0 {
		return 0
	}

	// ProcessTicks est en µs (depuis cgroup usage_usec ou cpuacct.usage/1000)
	deltaProcessUsec := snapEnd.ProcessTicks - snapStart.ProcessTicks

	// Convertir les ticks socket USER_HZ → µs
	// 1 tick = 10ms = 10000µs (USER_HZ=100)
	const tickToUsec = int64(10000)
	deltaTotalUsec := (snapEnd.TotalTicks - snapStart.TotalTicks) * tickToUsec
	deltaIdleUsec  := (snapEnd.IdleTicks  - snapStart.IdleTicks)  * tickToUsec

	if deltaTotalUsec <= 0 || deltaProcessUsec <= 0 {
		return 0
	}

	deltaNonIdleUsec := deltaTotalUsec - deltaIdleUsec
	if deltaNonIdleUsec <= 0 {
		return 0
	}

	cpuRatio := float64(deltaProcessUsec) / float64(deltaNonIdleUsec)
	if cpuRatio > 1.0 {
		cpuRatio = 1.0
	}

	attributed := int64(float64(deltaRAPL) * cpuRatio)

	log.Printf("attributedEnergyUJ: deltaRAPL=%dµJ processUsec=%d nonIdleUsec=%d cpuRatio=%.4f => attributed=%dµJ",
		deltaRAPL, deltaProcessUsec, deltaNonIdleUsec, cpuRatio, attributed)

	return attributed
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