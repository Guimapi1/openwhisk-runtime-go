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
	"time"

	"github.com/apache/openwhisk-runtime-go/openwhisk"
)

var failed = false

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
		InterruptionClass: "KILL_SAFE",
	}
	out, ierr, killInfo := proc2.Interact([]byte(`{"value":{}}`), energy)
	check("Full round trip: EXECUTION_PAUSED sent to embedded scheduler", pausedEventReceived, fmt.Sprintf("pausedEventReceived=%v", pausedEventReceived))
	check("Full round trip: no EXECUTION_KILLED (resume was granted)", !killedEventReceived, fmt.Sprintf("killedEventReceived=%v", killedEventReceived))
	check("Full round trip: process resumed and completed (killInfo nil)", killInfo == nil, fmt.Sprintf("killInfo=%v interactErr=%v", killInfo, ierr))
	check("Full round trip: action's real output received", ierr == nil && len(out) > 0, fmt.Sprintf("out=%q err=%v", string(out), ierr))
	proc2.Stop()

	fmt.Println("---")
	if failed {
		fmt.Println("RESULT: FAIL — see [FAIL] lines above")
		os.Exit(1)
	}
	fmt.Println("RESULT: ALL CHECKS PASSED")
}
