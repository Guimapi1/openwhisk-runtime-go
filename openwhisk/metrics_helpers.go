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
type CPUSnapshot struct {
	ProcessTicks int64 // utime + stime du pid cible (en ticks USER_HZ)
	TotalTicks   int64 // somme de tous les cores depuis /proc/stat
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
// En cas d'erreur, retourne 2^32 µJ (~4.29 kJ) qui couvre la grande majorité
// des implémentations Intel connues.
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
// L'overflow se produit quand le compteur dépasse max_energy_range_uj et
// repart de zéro — dans ce cas energyEnd < energyStart.
func deltaRAPLUJ(start, end int64) int64 {
	if end >= start {
		return end - start
	}
	// Overflow : le registre a dépassé son maximum et recommencé depuis 0.
	max := readRAPLMax()
	return (max - start) + end
}

// readProcessTicks lit utime + stime du processus pid depuis /proc/<pid>/stat.
// Ces valeurs sont exprimées en ticks (USER_HZ, généralement 100/s).
func readProcessTicks(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Format /proc/<pid>/stat : pid (comm) state ppid ...
	// On cherche la dernière ')' pour gérer les espaces dans le nom du processus.
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	// Après ')' : state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
	// flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("/proc/%d/stat: not enough fields", pid)
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

// readTotalTicks lit la somme des ticks CPU depuis /proc/stat.
// Si RAPL_CORES est défini (ex: "26-51,78-103"), on ne somme que les cores
// de ce socket pour que le dénominateur de pondération soit cohérent avec
// le registre RAPL lu. Sinon on somme tous les cores (ligne "cpu ").
func readTotalTicks() (int64, error) {
	coreMask := os.Getenv("RAPL_CORES")

	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}

	// Sans filtre de cores : ligne agrégée "cpu "
	if coreMask == "" {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "cpu ") {
				continue
			}
			fields := strings.Fields(line)
			var total int64
			for _, f := range fields[1:] {
				v, err := strconv.ParseInt(f, 10, 64)
				if err == nil {
					total += v
				}
			}
			return total, nil
		}
		return 0, fmt.Errorf("/proc/stat: cpu line not found")
	}

	// Avec filtre : on somme uniquement les cores du socket cible.
	allowedCores := parseCoreMask(coreMask)
	var total int64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		coreID, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu"))
		if err != nil || !allowedCores[coreID] {
			continue
		}
		for _, f := range fields[1:] {
			v, err := strconv.ParseInt(f, 10, 64)
			if err == nil {
				total += v
			}
		}
		found = true
	}
	if !found {
		return 0, fmt.Errorf("/proc/stat: no matching cores found for mask %q", coreMask)
	}
	return total, nil
}

// readCPUSnapshot lit simultanément les ticks du processus et du nœud.
func readCPUSnapshot(pid int) CPUSnapshot {
	var snap CPUSnapshot
	var err error

	snap.ProcessTicks, err = readProcessTicks(pid)
	if err != nil {
		log.Printf("readCPUSnapshot pid=%d: %v", pid, err)
	}

	snap.TotalTicks, err = readTotalTicks()
	if err != nil {
		log.Printf("readCPUSnapshot total: %v", err)
	}
	return snap
}

// attributedEnergyUJ calcule la fraction d'énergie RAPL attribuée au processus
// via pondération CPU : delta_RAPL × (delta_process_ticks / delta_total_ticks).
//
// Retourne 0 si les ticks CPU sont insuffisants (action trop courte < ~10ms)
// ou si RAPL n'est pas disponible. Ce cas sera traité ultérieurement.
func attributedEnergyUJ(energyStart, energyEnd int64, snapStart, snapEnd CPUSnapshot) int64 {
	delta := deltaRAPLUJ(energyStart, energyEnd)
	if delta <= 0 {
		return 0
	}

	deltaProcess := snapEnd.ProcessTicks - snapStart.ProcessTicks
	deltaTotal := snapEnd.TotalTicks - snapStart.TotalTicks

	if deltaTotal <= 0 || deltaProcess <= 0 {
		return 0
	}
	if deltaProcess > deltaTotal {
		deltaProcess = deltaTotal
	}
	return delta * deltaProcess / deltaTotal
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