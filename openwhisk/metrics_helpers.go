package openwhisk

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)



func readEnergy() (int64, error) {
	raplPath := os.Getenv("RAPL_PATH")

	if raplPath == "" {
		raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:1/intel-rapl:1:0/energy_uj"
	}

	dat, err := os.ReadFile(raplPath)

	if err != nil {
		return 0, err
	}

	return strconv.ParseInt(strings.TrimSpace(string(dat)), 10, 64)
}

func (ap *ActionProxy) recordMetrics(endpoint string, start, energyStart int64, meta *RunMeta) {
	energyEnd, err := readEnergy()
	if err != nil {
		log.Printf("readEnergy end %s: %v", endpoint, err)
	}

	end := time.Now().UnixNano()

	
	entry := Entry{
		Start:       start,
		End:         end,
		EnergyStart: energyStart,
		EnergyEnd:   energyEnd,
	}
	if meta != nil {
		entry.TraceID      = meta.TraceID
		entry.PodName  = meta.PodName
		entry.ActivationID = meta.ActivationID
	}

	if ap.metrics != nil {
		ap.metrics.Add(endpoint, start, end, energyStart, energyEnd, meta)
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