/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openwhisk

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

// OutputGuard constant string
const OutputGuard = "XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX\n"

// DefaultTimeoutStart to wait for a process to start
var DefaultTimeoutStart = 5 * time.Millisecond

// Executor is the container and the guardian  of a child process
// It starts a command, feeds input and output, read logs and control its termination
//
// controller (CLAUDE.md §7.3, §7.4; PLAYBOOK.md Phase 7's resolved open
// question #3) owns the dedicated cgroup v2 group the process is placed
// into at Start() time (CLONE_INTO_CGROUP) and is the SOLE freeze/
// resume/kill path from this phase on — energyMonitor.go's earlier
// killProcessGroup() (a bare process-group SIGKILL) is removed, not kept
// alongside this: CLAUDE.md §7.3 requires covering every descendant
// reliably, including ones that escape the process group via setsid(),
// which only cgroup.kill actually guarantees.
type Executor struct {
	cmd        *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Reader
	exited     chan bool
	controller *ActivationController
}

// execCounter names each activation's dedicated cgroup uniquely within
// this process (NewActivationController requires a fresh, not-yet-
// existing directory).
var execCounter int64

// NewExecutor creates a child subprocess using the provided command line,
// writing the logs in the given file.
// You can then start it getting a communication channel
//
// Returns nil if this environment cannot provide the cgroup delegation
// CLAUDE.md §7.3 requires (an already-cgroup-v2-mounted, writable
// subtree) — never a silent fallback to a non-cgroup process launch,
// which would quietly drop the freeze/kill guarantee for every action
// this container ever runs. See PLAYBOOK.md Phase 7's report for the
// infrastructure prerequisite this implies (Helm chart securityContext /
// cgroup delegation) for the currently-deployed cluster.
func NewExecutor(logout *os.File, logerr *os.File, command string, env map[string]string, args ...string) (proc *Executor) {
	cmd := exec.Command(command, args...)
	cmd.Stdout = logout
	cmd.Stderr = logerr
	// SysProcAttr (Setpgid + CgroupFD/UseCgroupFD) is set by
	// controller.Start() below, at process-creation time — not here.
	cmd.Env = []string{}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	Debug("env: %v", cmd.Env)
	if Debugging {
		cmd.Env = append(cmd.Env, "OW_DEBUG=/tmp/action.log")
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil
	}
	pipeOut, pipeIn, err := os.Pipe()
	if err != nil {
		return nil
	}
	cmd.ExtraFiles = []*os.File{pipeIn}
	output := bufio.NewReader(pipeOut)

	name := fmt.Sprintf("exec-%d-%d", os.Getpid(), atomic.AddInt64(&execCounter, 1))
	controller, err := NewActivationController(name)
	if err != nil {
		log.Printf(
			"[executor] cannot create activation cgroup %q: %v — this "+
				"environment's cgroup delegation does not support CLAUDE.md "+
				"§7.3's freeze/kill mechanism; action cannot start "+
				"(PLAYBOOK.md Phase 7 report: this requires Helm chart "+
				"securityContext / cgroup-delegation changes on the target "+
				"cluster).",
			name, err,
		)
		return nil
	}

	return &Executor{
		cmd,
		input,
		output,
		make(chan bool),
		controller,
	}
}

// Pid returns the PID of the underlying process, or 0 if not started.
func (proc *Executor) Pid() int {
	if proc.cmd != nil && proc.cmd.Process != nil {
		return proc.cmd.Process.Pid
	}
	return 0
}

// Interact interacts with the underlying process.
//
// energy carries the energy_* fields extracted by the sidecar (phase 3,
// energy_state.go::ExtractEnergyState — CLAUDE.md §7.2, §7.5): nil when
// no energy state was present at all (§7.5's third case), equivalent to
// a disabled threshold. Only ExecutionThresholdJ, ConsumedBeforeJ,
// PauseEnabled and the trace/reservation IDs are actually exercised this
// phase — PauseMode/MaxPause*/InterruptionClass are carried through for
// forward-compatibility with phases 6/7 but unused here.
//
// The third return value is non-nil exactly when the energy monitor
// killed the process locally and synchronously because
// consumed_before_j + energy measured this step reached
// ExecutionThresholdJ with PauseEnabled=false (CLAUDE.md §3.1: no
// scheduler round-trip before this kill — that would open an unbounded
// overshoot window). nil for a normal completion or an unrelated failure.
func (proc *Executor) Interact(in []byte, energy *EnergyState) ([]byte, error, *EnergyKillInfo) {
	// input to the subprocess
	proc.input.Write(in)
	proc.input.Write([]byte("\n"))

	chout := make(chan []byte)
	go func() {
		out, err := proc.output.ReadBytes('\n')
		if err == nil {
			chout <- out
		} else {
			chout <- []byte{}
		}
	}()

	var monitorResult *energyMonitorResult
	var monitorStop chan struct{}
	var monitorFinished chan struct{}
	if shouldMonitorEnergy(energy) {
		monitorResult = &energyMonitorResult{}
		monitorStop = make(chan struct{})
		monitorFinished = make(chan struct{})
		go proc.monitorEnergy(energy, monitorStop, monitorFinished, monitorResult)
	}

	var err error
	var out []byte
	select {
	case out = <-chout:
		if len(out) == 0 {
			err = errors.New("no answer from the action")
		}
	case <-proc.exited:
		err = errors.New("command exited")
	}

	var killInfo *EnergyKillInfo
	if monitorResult != nil {
		// Stop the monitor and wait for it to have fully returned before
		// reading its result — otherwise a kill decided concurrently,
		// right as the select above unblocks for an unrelated reason,
		// could race with this read (CLAUDE.md §7.1: the runtime must
		// report kills accurately, not lose or fabricate one at a timing
		// boundary).
		close(monitorStop)
		<-monitorFinished
		if killed, consumedJ, pauseID := monitorResult.get(); killed {
			killInfo = &EnergyKillInfo{EnergyConsumedJ: consumedJ, PauseID: pauseID}
		}
	}

	proc.cmd.Stdout.Write([]byte(OutputGuard))
	proc.cmd.Stderr.Write([]byte(OutputGuard))
	return out, err, killInfo
}

// Exited checks if the underlying command exited
func (proc *Executor) Exited() bool {
	select {
	case <-proc.exited:
		return true
	default:
		return false
	}
}

// ActionAck is the expected data structure for the action acknowledgement
type ActionAck struct {
	Ok bool `json:"ok"`
}

// Start execution of the command
// if the flag ack is true, wait forever for an acknowledgement
// if the flag ack is false wait a bit to check if the command exited
// returns an error if the program fails
func (proc *Executor) Start(waitForAck bool) error {
	// start the underlying executable, placed directly into its
	// dedicated cgroup at creation time (CLONE_INTO_CGROUP, CLAUDE.md
	// §7.3) rather than a bare cmd.Start().
	Debug("Start:")
	err := proc.controller.Start(proc.cmd)
	if err != nil {
		Debug("run: early exit")
		proc.cmd = nil // no need to kill
		return fmt.Errorf("command exited")
	}
	Debug("pid: %d", proc.cmd.Process.Pid)

	go func() {
		// Shared with ActivationController.killExecution()'s own
		// confirmation wait (waitOnce, cgroupFreezer.go) — exec.Cmd.Wait()
		// must never be called more than once on the same *exec.Cmd.
		proc.controller.WaitForExit()
		proc.exited <- true
	}()

	// not waiting for an ack, so use a timeout
	if !waitForAck {
		select {
		case <-proc.exited:
			return fmt.Errorf("command exited")
		case <-time.After(DefaultTimeoutStart):
			return nil
		}
	}

	// wait for acknowledgement
	Debug("waiting for an ack")
	ack := make(chan error)
	go func() {
		out, err := proc.output.ReadBytes('\n')
		Debug("received ack %s", out)
		if err != nil {
			ack <- err
			return
		}
		// parse ack
		var ackData ActionAck
		err = json.Unmarshal(out, &ackData)
		if err != nil {
			ack <- err
			return
		}
		// check ack
		if !ackData.Ok {
			ack <- fmt.Errorf("The action did not initialize properly.")
			return
		}
		ack <- nil
	}()
	// wait for ack or unexpected termination
	select {
	// ack received
	case err = <-ack:
		return err
	// process exited
	case <-proc.exited:
		return fmt.Errorf("Command exited abruptly during initialization.")
	}
}

// Stop will kill the process
// and close the channels
func (proc *Executor) Stop() {
	Debug("stopping")
	if proc.controller != nil {
		// No particular trace/reservation/pause is active here (Stop() is
		// a container-lifecycle shutdown, e.g. swapping in a new action
		// version — CLAUDE.md's identifiers are meaningless in that
		// context); killExecution() is idempotent regardless of the
		// current state (RUNNING, FROZEN, or already STOPPED by the
		// energy monitor).
		if err := proc.controller.killExecution("", "", "shutdown"); err != nil {
			log.Printf("[executor] killExecution during Stop() failed: %v", err)
		}
		if err := proc.controller.Close(); err != nil {
			log.Printf("[executor] failed to remove activation cgroup during Stop(): %v", err)
		}
	}
	proc.cmd = nil
}
