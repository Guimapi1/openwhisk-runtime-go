package openwhisk

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const raplPath = "/sys/class/powercap/intel-rapl/intel-rapl:1/intel-rapl:1:0/energy_uj"

func readEnergy() (int64, error) {
	dat, err := os.ReadFile(raplPath)

	if err != nil {
		return 0, err
	}

	return strconv.ParseInt(strings.TrimSpace(string(dat)), 10, 64)
}

func (ap *ActionProxy) recordMetrics(endpoint string, start, energyStart int64) {
    energyEnd, err := readEnergy()
    if err != nil {
        log.Printf("readEnergy end %s: %v", endpoint, err)
    }
    if ap.metrics != nil {
        ap.metrics.Add(endpoint, start, time.Now().UnixNano(), energyStart, energyEnd)
    }
}