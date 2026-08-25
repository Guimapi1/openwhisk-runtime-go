// verify_cgroup_pod is throwaway verification tooling (PLAYBOOK.md
// Phase 7's open question #4, redone with the correct deployment model:
// Kubernetes pods via the real invoker pod-template, not a generic
// Docker container). It drives the ACTUAL openwhisk.Executor /
// ActivationController code — not a shell re-implementation — through a
// full freeze -> EXECUTION_PAUSED -> RESUME_EXECUTION -> resume cycle,
// against a real embedded HTTP scheduler stand-in, and reports PASS/FAIL
// for each step. Meant to be built, copied into a real action pod via
// kubectl cp, and run there; not part of the shipped runtime.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apache/openwhisk-runtime-go/openwhisk"
)

var failed = false

// readEnergyProbe reads the REAL RAPL counter directly (not through the
// openwhisk package's own unexported readEnergy(), and deliberately
// independent of any RAPL_PATH override this binary may have set for
// earlier sections' determinism tricks — Section 4 unsets that override
// before calling this, to see the actual hardware counter).
func readEnergyProbe() (int64, error) {
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

// readUsageUsec reads usage_usec from a cgroups v2 cpu.stat file directly
// (mirrors readCgroupV2CPUUsec, unexported in the openwhisk package).
func readUsageUsec(cpuStatPath string) int64 {
	dat, err := os.ReadFile(cpuStatPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(dat), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "usage_usec" {
			if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func check(name string, ok bool, detail string) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failed = true
	}
	fmt.Printf("[%s] %s: %s\n", status, name, detail)
}

func writeScript(content string) (string, error) {
	f, err := ioutil.TempFile("", "verify_*.sh")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(f.Name(), 0755); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func main() {
	os.Setenv("ENERGY_MONITOR_INTERVAL_MS", "10")

	// Fake RAPL: fixed reading, deterministic threshold-hit-on-first-tick
	// trick shared with the real test suite's executor_test.go.
	raplFile, err := ioutil.TempFile("", "fake_rapl_*.txt")
	if err != nil {
		fmt.Println("setup error:", err)
		os.Exit(1)
	}
	raplFile.WriteString("1000000")
	raplFile.Close()
	os.Setenv("RAPL_PATH", raplFile.Name())

	// --- Embedded scheduler stand-in: real HTTP server, real JSON wire
	// format, running inside THIS pod's network namespace. ---
	var pausedEventReceived bool
	var killedEventReceived bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		var generic map[string]interface{}
		json.Unmarshal(body, &generic)
		w.Header().Set("Content-Type", "application/json")
		switch generic["event"] {
		case "EXECUTION_PAUSED":
			pausedEventReceived = true
			var ev openwhisk.ExecutionPausedEvent
			json.Unmarshal(body, &ev)
			cmd := openwhisk.SchedulerCommand{
				Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
				ReservationID: ev.ReservationID, PauseID: ev.PauseID,
				NewExecutionThresholdJ: 1e9,
			}
			json.NewEncoder(w).Encode(cmd)
		case "EXECUTION_KILLED":
			killedEventReceived = true
			json.NewEncoder(w).Encode(map[string]bool{"ack": true})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	os.Setenv("SCHEDULER_URL", server.URL)
	fmt.Println("embedded scheduler stand-in listening at", server.URL)

	// --- 1. Raw ActivationController primitives (mirrors
	// cgroupFreezer_test.go, run here for real inside this pod). ---
	logf, _ := ioutil.TempFile("", "log")
	scriptPath, err := writeScript("#!/bin/sh\ni=0\nwhile true; do i=$((i+1)); echo $i > \"$1\"; sleep 0.05; done\n")
	if err != nil {
		fmt.Println("setup error:", err)
		os.Exit(1)
	}
	counterFile, _ := ioutil.TempFile("", "counter_*.txt")
	counterFile.Close()

	proc1 := openwhisk.NewExecutor(logf, logf, scriptPath, map[string]string{}, counterFile.Name())
	check("NewExecutor (creates dedicated cgroup, CLAUDE.md §7.3)", proc1 != nil, fmt.Sprintf("proc=%v", proc1 != nil))
	if proc1 == nil {
		fmt.Println("ABORTING: cgroup delegation is not available in this pod — cannot continue.")
		os.Exit(1)
	}

	err = proc1.Start(false)
	check("Executor.Start (CLONE_INTO_CGROUP process placement)", err == nil, fmt.Sprintf("err=%v", err))
	time.Sleep(300 * time.Millisecond)

	vBefore, _ := ioutil.ReadFile(counterFile.Name())
	check("counter process is progressing before Stop", len(vBefore) > 0, fmt.Sprintf("counter=%q", string(vBefore)))

	proc1.Stop() // exercises killExecution via Stop() (cgroup.kill)
	time.Sleep(200 * time.Millisecond)
	vAfterStop, _ := ioutil.ReadFile(counterFile.Name())
	time.Sleep(200 * time.Millisecond)
	vAfterWait, _ := ioutil.ReadFile(counterFile.Name())
	check(
		"Executor.Stop kills the counter process (via killExecution/cgroup.kill, no further progress)",
		string(vAfterStop) == string(vAfterWait),
		fmt.Sprintf("right-after-stop=%q after-extra-wait=%q", string(vAfterStop), string(vAfterWait)),
	)

	// --- 2. Full pause/resume round trip through Executor.Interact(),
	// exactly as runHandler.go drives it, against the embedded scheduler
	// stand-in above. ---
	logf2, _ := ioutil.TempFile("", "log2")
	respondScript, err := writeScript("#!/bin/sh\nwhile read a; do sleep 0.3; echo '{\"ok\": true}' >&3; done\n")
	if err != nil {
		fmt.Println("setup error:", err)
		os.Exit(1)
	}
	proc2 := openwhisk.NewExecutor(logf2, logf2, respondScript, map[string]string{})
	check("NewExecutor #2 (second dedicated cgroup)", proc2 != nil, "")
	if proc2 == nil {
		os.Exit(1)
	}
	err = proc2.Start(false)
	check("Executor.Start #2", err == nil, fmt.Sprintf("err=%v", err))

	energy := &openwhisk.EnergyState{
		TraceID: "verify-pod-trace", ReservationID: "verify-pod-trace",
		ExecutionPhase: "forward", ExecutionThresholdJ: 1.0, ConsumedBeforeJ: 1.0,
		PauseEnabled: true, PauseMode: "CGROUP_FREEZE", MaxPauseDurationMs: 2000, MaxPauseCount: 1,
		// Per-component map (CLAUDE.md §0 decision 15) keyed by
		// __OW_ACTION_NAME — unset in this standalone binary's own
		// environment, so the lookup key is "".
		InterruptionClass: map[string]string{"": "KILL_SAFE"},
	}
	out, ierr, killInfo := proc2.Interact([]byte(`{"value":{}}`), energy)
	check("Full round trip: EXECUTION_PAUSED sent to embedded scheduler", pausedEventReceived, fmt.Sprintf("pausedEventReceived=%v", pausedEventReceived))
	check("Full round trip: no EXECUTION_KILLED (resume was granted)", !killedEventReceived, fmt.Sprintf("killedEventReceived=%v", killedEventReceived))
	check("Full round trip: process resumed and completed (killInfo nil)", killInfo == nil, fmt.Sprintf("killInfo=%v interactErr=%v", killInfo, ierr))
	check("Full round trip: action's real output received", ierr == nil && len(out) > 0, fmt.Sprintf("out=%q err=%v", string(out), ierr))
	proc2.Stop()

	// --- 3. Cgroup path comparison + usage_usec growth over a REAL
	// multi-second CPU-busy window (investigation of the freeze
	// mechanism never triggering on real long-running fraud_check/
	// reserve_stock invocations — see the session's diagnostic
	// findings). Compares (a) ActivationController.CgroupPath(), the
	// path CLONE_INTO_CGROUP actually placed the process into, against
	// (b) openwhisk.ResolveCgroupCPUStatPath(pid), what readProcessTicks
	// itself would independently resolve for the SAME pid — then samples
	// usage_usec repeatedly over ~4s of real CPU work to see directly
	// whether it grows (as it must, for the energy monitor's threshold
	// comparison to ever mean anything) or stays frozen.
	fmt.Println("\n--- Section 3: cgroup path comparison + usage_usec growth ---")
	logf3, _ := ioutil.TempFile("", "log3")
	busyScript, err := writeScript(
		"#!/bin/sh\ni=0\nwhile read a; do\n" +
			"  end=$(($(date +%s) + 4))\n" +
			"  while [ \"$(date +%s)\" -lt \"$end\" ]; do i=$((i+1)); done\n" +
			"  echo '{\"ok\": true}' >&3\n" +
			"done\n",
	)
	if err != nil {
		fmt.Println("setup error:", err)
		os.Exit(1)
	}
	proc3 := openwhisk.NewExecutor(logf3, logf3, busyScript, map[string]string{})
	check("NewExecutor #3 (third dedicated cgroup, for path/growth check)", proc3 != nil, "")
	if proc3 == nil {
		os.Exit(1)
	}
	if err := proc3.Start(false); err != nil {
		fmt.Println("proc3.Start error:", err)
		os.Exit(1)
	}

	controllerPath := proc3.CgroupPath()
	resolvedStatPath, resolveErr := openwhisk.ResolveCgroupCPUStatPath(proc3.Pid())
	expectedStatPath := controllerPath + "/cpu.stat"
	check(
		"Path match: ActivationController.CgroupPath() vs readProcessTicks' own resolution",
		resolveErr == nil && resolvedStatPath == expectedStatPath,
		fmt.Sprintf("pid=%d controller_path=%q expected_stat_path=%q resolved_stat_path=%q resolve_err=%v",
			proc3.Pid(), controllerPath, expectedStatPath, resolvedStatPath, resolveErr),
	)

	// Kick off the busy work (respondScript-style: writes to stdin,
	// reads the fd3 response asynchronously so we can sample while it runs).
	go func() {
		_, _, _ = proc3.Interact([]byte(`{"value":{}}`), nil)
	}()
	time.Sleep(100 * time.Millisecond) // let the busy loop actually start

	fmt.Println("Sampling usage_usec every 500ms for ~4s of real CPU work:")
	var samples []int64
	for i := 0; i < 8; i++ {
		if resolveErr == nil {
			if dat, err := ioutil.ReadFile(resolvedStatPath); err == nil {
				var usec int64
				for _, line := range strings.Split(string(dat), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 2 && fields[0] == "usage_usec" {
						if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
							usec = n
						}
					}
				}
				samples = append(samples, usec)
				fmt.Printf("  t=%.1fs usage_usec=%d\n", float64(i)*0.5, usec)
			} else {
				fmt.Printf("  t=%.1fs read error: %v\n", float64(i)*0.5, err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	growing := len(samples) >= 2 && samples[len(samples)-1] > samples[0]
	check(
		"usage_usec actually grows over ~4s of real CPU work (not frozen)",
		growing,
		fmt.Sprintf("samples=%v", samples),
	)
	proc3.Stop()

	// --- 4. I/O-bound workload, REAL RAPL, through the ACTUAL
	// Interact()/monitorEnergy() code path with a genuine EnergyState —
	// unlike Section 3 (energy=nil, monitoring never engaged; raw file
	// polling done separately in main.go itself), this drives the real
	// production threshold-detection loop. Tests the hypothesis from the
	// session's investigation: reserve_stock/fraud_check are mostly
	// BLOCKED on Postgres round trips (near-zero CPU-time) even though
	// wall-clock (and real RAPL draw) keeps growing — does the live
	// monitor ever detect a crossing for that shape of workload, or does
	// attributedEnergyUJ's CPU-time-share model ("same logic as Kepler")
	// stay blind throughout? Simulated here with sleep-heavy iterations
	// (no real DB dependency needed) rather than reusing Sections 1-3's
	// fixed fake RAPL reading, which would make this meaningless — this
	// section needs the real hardware counter.
	fmt.Println("\n--- Section 4: I/O-bound workload, REAL RAPL, does the live monitor ever fire? ---")
	os.Unsetenv("RAPL_PATH")
	if _, raplErr := readEnergyProbe(); raplErr != nil {
		fmt.Printf("[SKIP] Section 4: real RAPL not readable in this pod (%v) — cannot test this hypothesis here.\n", raplErr)
	} else {
		logf4, _ := ioutil.TempFile("", "log4")
		// ~250 iterations x 12ms sleep = ~3s wall-clock, negligible CPU —
		// mimics an I/O-bound action mostly blocked on network round
		// trips (like reserve_stock/fraud_check's Postgres calls).
		ioScript, err := writeScript(
			"#!/bin/sh\nwhile read a; do\n" +
				"  i=0\n" +
				"  while [ \"$i\" -lt 250 ]; do i=$((i+1)); sleep 0.012; done\n" +
				"  echo '{\"ok\": true}' >&3\n" +
				"done\n",
		)
		if err != nil {
			fmt.Println("setup error:", err)
			os.Exit(1)
		}
		proc4 := openwhisk.NewExecutor(logf4, logf4, ioScript, map[string]string{})
		check("NewExecutor #4 (fourth dedicated cgroup, I/O-bound test)", proc4 != nil, "")
		if proc4 != nil {
			pausedEventReceived = false
			killedEventReceived = false

			energy4 := &openwhisk.EnergyState{
				TraceID: "verify-pod-io-trace", ReservationID: "verify-pod-io-trace",
				ExecutionPhase: "forward",
				// Deliberately small — a real ~3s wall-clock window on a
				// real socket should genuinely exceed this in true RAPL
				// terms, if that energy were correctly attributed.
				ExecutionThresholdJ: 0.05, ConsumedBeforeJ: 0.0,
				PauseEnabled: true, PauseMode: "CGROUP_FREEZE", MaxPauseDurationMs: 2000, MaxPauseCount: 1,
				InterruptionClass: map[string]string{"": "KILL_SAFE"},
			}

			beforeEnergy, _ := readEnergyProbe()
			beforePath, _ := openwhisk.ResolveCgroupCPUStatPath(proc4.Pid())
			var beforeUsec int64
			if beforePath != "" {
				beforeUsec = readUsageUsec(beforePath)
			}
			startedAt := time.Now()

			out4, ierr4, killInfo4 := proc4.Interact([]byte(`{"value":{}}`), energy4)

			elapsed := time.Since(startedAt)
			afterEnergy, _ := readEnergyProbe()
			var afterUsec int64
			if beforePath != "" {
				afterUsec = readUsageUsec(beforePath)
			}

			realDeltaRAPLJ := float64(afterEnergy-beforeEnergy) / 1e6
			realDeltaProcessUsec := afterUsec - beforeUsec
			cpuTimeShare := float64(realDeltaProcessUsec) / (elapsed.Seconds() * 1e6 * float64(runtime.NumCPU()))

			fmt.Printf(
				"  elapsed=%.2fs real_delta_RAPL_J=%.4f real_delta_process_usec=%d cpu_time_share=%.6f\n",
				elapsed.Seconds(), realDeltaRAPLJ, realDeltaProcessUsec, cpuTimeShare,
			)
			check(
				"Interact() completed without error (I/O-bound workload)",
				ierr4 == nil,
				fmt.Sprintf("out=%q err=%v killInfo=%v", string(out4), ierr4, killInfo4),
			)
			realEnergyExceededThreshold := realDeltaRAPLJ > energy4.ExecutionThresholdJ
			neverFroze := !pausedEventReceived && !killedEventReceived && killInfo4 == nil
			if realEnergyExceededThreshold {
				check(
					"HYPOTHESIS: real RAPL alone exceeded threshold_j, but the live "+
						"monitor's attribution model never froze/killed this I/O-bound workload",
					neverFroze,
					fmt.Sprintf(
						"pausedEventReceived=%v killedEventReceived=%v killInfo=%v — "+
							"real_delta_RAPL_J=%.4f vs threshold_j=%.4f — cpu_time_share=%.6f",
						pausedEventReceived, killedEventReceived, killInfo4,
						realDeltaRAPLJ, energy4.ExecutionThresholdJ, cpuTimeShare,
					),
				)
			} else {
				fmt.Printf(
					"  [INCONCLUSIVE] real_delta_RAPL_J=%.4f did not exceed threshold_j=%.4f "+
						"on its own — background power draw too low or window too short for "+
						"this specific run to distinguish the hypothesis; raise ExecutionThresholdJ "+
						"or the sleep loop's total duration and retry. "+
						"(pausedEventReceived=%v killedEventReceived=%v killInfo=%v, cpu_time_share=%.6f)\n",
					realDeltaRAPLJ, energy4.ExecutionThresholdJ,
					pausedEventReceived, killedEventReceived, killInfo4, cpuTimeShare,
				)
			}
			proc4.Stop()
		}
	}

	fmt.Println("---")
	if failed {
		fmt.Println("RESULT: FAIL — see [FAIL] lines above")
		os.Exit(1)
	}
	fmt.Println("RESULT: ALL CHECKS PASSED")
}
