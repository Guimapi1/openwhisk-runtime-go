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

	if ap.metrics != nil {
		ap.metrics.Add(endpoint, start, end, energyStart, energyEnd, meta)
	}

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

	// push asynchrone pour ne pas bloquer la réponse HTTP
	go pushMetrics(endpoint, entry)
}