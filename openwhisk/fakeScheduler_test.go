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

// fakeScheduler_test.go: a minimal stand-in for the scheduler's
// dedicated /api/v1/energy/events channel (CLAUDE.md §6.5, §6.6, §7.6),
// shared by executor_test.go's and energyMonitor_test.go's Phase 7
// tests. Exercises the runtime's REAL HTTP client (schedulerChannel.go)
// against a REAL httptest.Server — only the scheduler's own Python-side
// decision logic (core/scheduler.py) is stood in for here, matching this
// repo's own convention (see energy_state.go's header: OpenWhisk's own
// sequence chaining is verified separately, against a live cluster;
// cross-repo, cross-language integration is verified in its own
// end-to-end test).

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// waitFor polls cond every 10ms until it returns true or timeout
// elapses, failing the test in the latter case. Used to observe the
// effect of the fire-and-forget EXECUTION_KILLED POST (postExecutionKilled
// runs in its own goroutine, launched from runHandler.go, so it may not
// have landed on fakeSchedulerServer yet by the time /run's own response
// comes back).
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for: %s", msg)
	}
}

type fakeSchedulerServer struct {
	server *httptest.Server

	mu           sync.Mutex
	pausedEvents []ExecutionPausedEvent
	killedEvents []ExecutionKilledEvent
	// commandFunc computes the response to each EXECUTION_PAUSED event.
	// Defaults (if nil) to always granting RESUME_EXECUTION with a huge
	// threshold, so a test that doesn't care about the pause outcome can
	// just let the action keep running.
	commandFunc func(ExecutionPausedEvent) SchedulerCommand
}

func newFakeSchedulerServer(t *testing.T) *fakeSchedulerServer {
	t.Helper()
	fs := &fakeSchedulerServer{}
	fs.server = httptest.NewServer(http.HandlerFunc(fs.handle))
	t.Cleanup(fs.server.Close)
	t.Setenv("SCHEDULER_URL", fs.server.URL)
	return fs
}

func (fs *fakeSchedulerServer) handle(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(body, &generic); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	eventType, _ := generic["event"].(string)

	w.Header().Set("Content-Type", "application/json")

	switch eventType {
	case "EXECUTION_PAUSED":
		var ev ExecutionPausedEvent
		_ = json.Unmarshal(body, &ev)

		fs.mu.Lock()
		fs.pausedEvents = append(fs.pausedEvents, ev)
		fn := fs.commandFunc
		fs.mu.Unlock()

		var cmd SchedulerCommand
		if fn != nil {
			cmd = fn(ev)
		} else {
			cmd = SchedulerCommand{
				Command: "RESUME_EXECUTION", TraceID: ev.TraceID,
				ReservationID: ev.ReservationID, PauseID: ev.PauseID,
				NewExecutionThresholdJ: 1e9,
			}
		}
		_ = json.NewEncoder(w).Encode(cmd)

	case "EXECUTION_KILLED":
		var ev ExecutionKilledEvent
		_ = json.Unmarshal(body, &ev)

		fs.mu.Lock()
		fs.killedEvents = append(fs.killedEvents, ev)
		fs.mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]bool{"ack": true})

	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// setCommandFunc overrides how EXECUTION_PAUSED events are answered.
func (fs *fakeSchedulerServer) setCommandFunc(fn func(ExecutionPausedEvent) SchedulerCommand) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.commandFunc = fn
}

func (fs *fakeSchedulerServer) getPausedEvents() []ExecutionPausedEvent {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]ExecutionPausedEvent, len(fs.pausedEvents))
	copy(out, fs.pausedEvents)
	return out
}

func (fs *fakeSchedulerServer) getKilledEvents() []ExecutionKilledEvent {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]ExecutionKilledEvent, len(fs.killedEvents))
	copy(out, fs.killedEvents)
	return out
}
