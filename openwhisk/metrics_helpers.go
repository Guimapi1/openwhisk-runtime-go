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
	ProcessTicks int64 // utime + stime du pid cible (en ticks)
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
	// Le format de /proc/<pid>/stat est :
	// pid (comm) state ppid ... utime(14) stime(15) ...
	// On localise la fermeture de la parenthèse du champ comm pour éviter
	// les espaces éventuels dans le nom du processus.
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	fields := strings.Fields(s[closeParen+1:])
	// Après le ')' : state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5)
	// flags(6) minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12)
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

// readTotalTicks lit la somme des ticks CPU de tous les cores depuis /proc/stat.
// On utilise la ligne "cpu " (agrégat global) : user nice system idle iowait irq softirq ...
func readTotalTicks() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields[0] == "cpu", fields[1..] sont les compteurs
		var total int64
		for _, f := range fields[1:] {
			v, err := strconv.ParseInt(f, 10, 64)
			if err != nil {
				continue
			}
			total += v
		}
		return total, nil
	}
	return 0, fmt.Errorf("/proc/stat: cpu line not found")
}

// readCPUSnapshot lit simultanément les ticks du processus pid et du nœud.
// En cas d'erreur sur le processus (pid inconnu, action pas encore démarrée),
// on renvoie quand même le snapshot avec ProcessTicks=0 et l'erreur loggée.
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

// attributedEnergyUJ calcule la fraction d'énergie RAPL attribuée au processus.
// Si les deltas CPU sont nuls ou incohérents on renvoie 0 (pas d'estimation).
func attributedEnergyUJ(deltaRAPL int64, snapStart, snapEnd CPUSnapshot) int64 {
	deltaProcess := snapEnd.ProcessTicks - snapStart.ProcessTicks
	deltaTotal := snapEnd.TotalTicks - snapStart.TotalTicks

	if deltaTotal <= 0 || deltaProcess < 0 {
		return 0
	}
	if deltaProcess > deltaTotal {
		// Cas théoriquement impossible mais défensif
		deltaProcess = deltaTotal
	}
	return deltaRAPL * deltaProcess / deltaTotal
}

// recordMetrics calcule et enregistre les métriques énergétiques d'un endpoint.
// Elle doit être appelée APRÈS que l'action a répondu, avec les snapshots
// pris juste avant et juste après l'exécution.
func (ap *ActionProxy) recordMetrics(endpoint string, start, energyStart int64, cpuStart CPUSnapshot, meta *RunMeta) {
	// Lire les valeurs de fin le plus tôt possible
	energyEnd, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy end %s: %v", endpoint, err)
	}
	end := time.Now().UnixNano()

	var cpuEnd CPUSnapshot
	if ap.theExecutor != nil {
		cpuEnd = readCPUSnapshot(ap.theExecutor.Pid())
	}

	deltaRAPL := energyEnd - energyStart
	attributed := attributedEnergyUJ(deltaRAPL, cpuStart, cpuEnd)

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
		// Flusher le init en attente avec le trace_id maintenant connu
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
		// endpoint == "/init" : bufferiser sans pusher
		ap.pendingInitMu.Lock()
		ap.pendingInitEntry = &entry
		ap.pendingInitMu.Unlock()
	}
}