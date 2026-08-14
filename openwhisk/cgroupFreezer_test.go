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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cgroupFreezer_test.go: CLAUDE.md §7.3 (cgroup freezer) / §7.4 (runtime
// state machine), tested in isolation (not through Executor/runHandler —
// that round-trip is phase 7).
//
// These tests manipulate REAL cgroup v2 groups. requireCgroupV2 skips
// (never fakes success) if this environment doesn't grant the delegation
// needed — e.g. insufficient rights or no cgroup v2. In THIS repo's own
// CI/dev environment at the time this phase was written, real
// unprivileged cgroup v2 delegation (systemd user session, kernel 6.17)
// was confirmed available and these tests exercise it for real.

func requireCgroupV2(t *testing.T) {
	t.Helper()
	name := fmt.Sprintf("probe_%d", time.Now().UnixNano())
	cg, err := newCgroupHandle(name)
	if err != nil {
		t.Skipf("cgroup v2 delegation not available in this environment (%v) — skipping, not simulating success", err)
	}
	_ = cg.remove()
}

func uniqueCgroupName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s_%d", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano())
}

// newCounterScript returns a script that writes an ever-increasing
// integer to the file at $1 roughly every 20ms, so a test can observe
// whether the process is making progress or is genuinely frozen.
func newCounterScript(t *testing.T) string {
	return writeTempScript(t, "#!/bin/sh\n"+
		"i=0\n"+
		"while true; do\n"+
		"  i=$((i+1))\n"+
		"  echo $i > \"$1\"\n"+
		"  sleep 0.02\n"+
		"done\n")
}

// newParentWithChildCounterScript spawns a BACKGROUND child that does the
// counting (via newCounterScript's loop), while the parent just waits —
// used to prove the freeze covers descendants, not just the main PID.
func newParentWithChildCounterScript(t *testing.T) string {
	return writeTempScript(t, "#!/bin/sh\n"+
		"(\n"+
		"  i=0\n"+
		"  while true; do\n"+
		"    i=$((i+1))\n"+
		"    echo $i > \"$1\"\n"+
		"    sleep 0.02\n"+
		"  done\n"+
		") &\n"+
		"echo $! > \"$2\"\n"+
		"wait\n")
}

func readCounter(t *testing.T, path string) int {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return v
}

// waitForCounterAbove polls path until its integer content exceeds min,
// or the deadline passes (in which case the test fails).
func waitForCounterAbove(t *testing.T, path string, min int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v := readCounter(t, path); v > min {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.FailNow(t, fmt.Sprintf("counter at %s never exceeded %d within %s", path, min, timeout))
	return 0
}

func startCounterController(t *testing.T, script string) (*ActivationController, string) {
	t.Helper()
	ctrl, err := NewActivationController(uniqueCgroupName(t))
	require.NoError(t, err)

	counterFile, err := ioutil.TempFile("", "counter_*.txt")
	require.NoError(t, err)
	require.NoError(t, counterFile.Close())
	t.Cleanup(func() { os.Remove(counterFile.Name()) })

	cmd := exec.Command(script, counterFile.Name())
	require.NoError(t, ctrl.Start(cmd))

	t.Cleanup(func() {
		_ = ctrl.killExecution("t", "r", "cleanup")
		_ = ctrl.Close()
	})

	// Let it get going before the test starts asserting on it.
	waitForCounterAbove(t, counterFile.Name(), 0, 2*time.Second)
	return ctrl, counterFile.Name()
}

// 1. freezeExecution actually freezes the process and its descendants:
// verified both via cgroup.events readback (through the state machine's
// own success) and via the counter making no progress while frozen.
func TestActivationController_FreezeExecution_StopsProgress(t *testing.T) {
	requireCgroupV2(t)

	ctrl, counterFile := startCounterController(t, newCounterScript(t))

	err := ctrl.freezeExecution("trace-1", "trace-1", "pause-1")
	require.NoError(t, err)
	assert.Equal(t, StateFrozen, ctrl.State())

	before := readCounter(t, counterFile)
	time.Sleep(200 * time.Millisecond)
	after := readCounter(t, counterFile)
	assert.Equal(t, before, after, "counter must not advance while frozen")
}

// 2. resumeExecution after freeze restores normal execution.
func TestActivationController_ResumeExecution_RestoresProgress(t *testing.T) {
	requireCgroupV2(t)

	ctrl, counterFile := startCounterController(t, newCounterScript(t))

	require.NoError(t, ctrl.freezeExecution("trace-2", "trace-2", "pause-2"))
	frozenAt := readCounter(t, counterFile)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, frozenAt, readCounter(t, counterFile), "sanity: must be frozen before resuming")

	err := ctrl.resumeExecution("trace-2", "trace-2", "pause-2")
	require.NoError(t, err)
	assert.Equal(t, StateRunning, ctrl.State())

	waitForCounterAbove(t, counterFile, frozenAt, 2*time.Second)
}

// 3. killExecution from FROZEN, and from RUNNING, both reach STOPPED.
func TestActivationController_KillExecution_ReachesStoppedFromEitherState(t *testing.T) {
	requireCgroupV2(t)

	t.Run("from RUNNING", func(t *testing.T) {
		ctrl, _ := startCounterController(t, newCounterScript(t))
		require.Equal(t, StateRunning, ctrl.State())

		err := ctrl.killExecution("trace-3a", "trace-3a", "pause-3a")
		require.NoError(t, err)
		assert.Equal(t, StateStopped, ctrl.State())
		assert.False(t, processAlive(ctrl.Pid()))
	})

	t.Run("from FROZEN", func(t *testing.T) {
		ctrl, _ := startCounterController(t, newCounterScript(t))
		require.NoError(t, ctrl.freezeExecution("trace-3b", "trace-3b", "pause-3b"))
		require.Equal(t, StateFrozen, ctrl.State())

		err := ctrl.killExecution("trace-3b", "trace-3b", "pause-3b")
		require.NoError(t, err)
		assert.Equal(t, StateStopped, ctrl.State())
		assert.False(t, processAlive(ctrl.Pid()))
	})
}

// 4. Idempotence: calling freezeExecution twice with the same pauseID
// produces no error and no double transition.
func TestActivationController_FreezeExecution_IsIdempotentForSamePauseID(t *testing.T) {
	requireCgroupV2(t)

	ctrl, _ := startCounterController(t, newCounterScript(t))

	require.NoError(t, ctrl.freezeExecution("trace-4", "trace-4", "pause-4"))
	require.Equal(t, StateFrozen, ctrl.State())

	err := ctrl.freezeExecution("trace-4", "trace-4", "pause-4")
	assert.NoError(t, err)
	assert.Equal(t, StateFrozen, ctrl.State(), "repeat freeze under the same pause_id must not transition again")
}

// 5. An invalid transition (resumeExecution with no freeze in progress)
// produces the structured error event, not a silent crash or a nil error.
func TestActivationController_ResumeExecution_WithoutFreezeInProgress_ProducesStructuredError(t *testing.T) {
	requireCgroupV2(t)

	ctrl, err := NewActivationController(uniqueCgroupName(t))
	require.NoError(t, err)
	cmd := exec.Command(newCounterScript(t), os.DevNull)
	require.NoError(t, ctrl.Start(cmd))
	t.Cleanup(func() {
		_ = ctrl.killExecution("t", "r", "cleanup")
		_ = ctrl.Close()
	})
	require.Equal(t, StateRunning, ctrl.State())

	resumeErr := ctrl.resumeExecution("trace-5", "trace-5", "pause-5")

	require.Error(t, resumeErr)
	var transitionErr *TransitionError
	require.True(t, errors.As(resumeErr, &transitionErr), "expected a *TransitionError, got %T: %v", resumeErr, resumeErr)
	assert.Equal(t, "RUNTIME_STATE_TRANSITION_ERROR", transitionErr.Event)
	assert.Equal(t, "resume", transitionErr.AttemptedOp)
	assert.Equal(t, StateRunning, transitionErr.FromState)
	assert.Equal(t, "pause-5", transitionErr.PauseID)
	assert.NotEmpty(t, transitionErr.Reason)

	// No crash, and no state corruption: still RUNNING, not UNKNOWN.
	assert.Equal(t, StateRunning, ctrl.State())
}

// 6. The freeze covers a child process spawned by the action, not just
// the main PID.
func TestActivationController_FreezeExecution_CoversChildProcess(t *testing.T) {
	requireCgroupV2(t)

	ctrl, err := NewActivationController(uniqueCgroupName(t))
	require.NoError(t, err)

	counterFile, err := ioutil.TempFile("", "counter_*.txt")
	require.NoError(t, err)
	require.NoError(t, counterFile.Close())
	t.Cleanup(func() { os.Remove(counterFile.Name()) })

	childPidFile, err := ioutil.TempFile("", "childpid_*.txt")
	require.NoError(t, err)
	require.NoError(t, childPidFile.Close())
	t.Cleanup(func() { os.Remove(childPidFile.Name()) })

	cmd := exec.Command(newParentWithChildCounterScript(t), counterFile.Name(), childPidFile.Name())
	require.NoError(t, ctrl.Start(cmd))
	t.Cleanup(func() {
		_ = ctrl.killExecution("t", "r", "cleanup")
		_ = ctrl.Close()
	})

	waitForCounterAbove(t, counterFile.Name(), 0, 2*time.Second)

	// The counter is written by the CHILD, not the parent script itself
	// (which just backgrounds it and waits) — confirm the child is a
	// distinct, genuinely running process before freezing.
	var childPid int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, readErr := ioutil.ReadFile(childPidFile.Name()); readErr == nil && len(data) > 0 {
			if v, scanErr := strconv.Atoi(strings.TrimSpace(string(data))); scanErr == nil && v > 0 {
				childPid = v
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, childPid > 0, "child never reported its PID")
	require.NotEqual(t, ctrl.Pid(), childPid, "sanity: the child must be a distinct process from the parent")
	require.True(t, processAlive(childPid))

	require.NoError(t, ctrl.freezeExecution("trace-6", "trace-6", "pause-6"))

	before := readCounter(t, counterFile.Name())
	time.Sleep(200 * time.Millisecond)
	after := readCounter(t, counterFile.Name())
	assert.Equal(t, before, after, "the child's own counter must not advance while the group is frozen")
	assert.True(t, processAlive(childPid), "the child process itself must still exist (frozen, not killed)")

	// Killing the (still frozen) group must take the child down too —
	// the same guarantee energyMonitor.go's process-group kill (phase 5)
	// gives for pauseEnabled=false, now backed by the cgroup instead.
	require.NoError(t, ctrl.killExecution("trace-6", "trace-6", "pause-6"))
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(childPid) {
		time.Sleep(10 * time.Millisecond)
	}
	assert.False(t, processAlive(childPid), "child process must be killed along with the group")
}
