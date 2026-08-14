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

// schedulerChannel.go implements the Go side of the dedicated runtime ->
// scheduler HTTP channel (CLAUDE.md §6.5, §6.6, §7.6; PLAYBOOK.md
// Phase 7's resolved open questions #2/#3). The runtime is always the
// one making the OUTBOUND call to SCHEDULER_URL/api/v1/energy/events,
// because the scheduler has a stable, known address while an ephemeral
// action container does not have one the scheduler could call back on.
//
// EXECUTION_PAUSED (postExecutionPaused): the call BLOCKS until the
// scheduler responds — that response body IS the RESUME_EXECUTION /
// KILL_EXECUTION command (§7.5 step 7's "attendre une commande explicite
// du scheduler"). This replaces the earlier design (phase 5) where a
// pauseEnabled=false kill's EXECUTION_KILLED payload was embedded
// directly in the /run HTTP response — that channel cannot carry a
// PAUSE, since /run's caller (OpenWhisk itself) is not the scheduler and
// cannot answer with a command.
//
// EXECUTION_KILLED (postExecutionKilled): fire-and-forget, never blocks
// the /run response on it (CLAUDE.md §3.1: no round-trip before an
// already-decided kill). Used for BOTH the pauseEnabled=false immediate
// kill and this phase's own pause-cycle kill fallback — cgroup.kill
// (killExecution) is the only kill path either way (open question #3).

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// schedulerURL returns the scheduler's base URL, overridable via
// SCHEDULER_URL (this repo's convention: env vars read directly where
// used, no centralized config.go on the Go side — see cgroupFreezer.go,
// energyMonitor.go).
func schedulerURL() string {
	if v := os.Getenv("SCHEDULER_URL"); v != "" {
		return v
	}
	return "http://localhost:5000"
}

func schedulerEventsEndpoint() string {
	return schedulerURL() + "/api/v1/energy/events"
}

// schedulerChannelTimeoutMarginMs reads SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS
// (default 2000ms): the safety margin added on top of the pause cycle's
// own max_pause_duration_ms when bounding the blocking EXECUTION_PAUSED
// call (see pausedEventTimeout) — covers network latency and the
// scheduler's own processing time around its internal deadline, so a
// legitimate-but-slightly-late scheduler decision is never mistaken for
// a network failure and turned into a spurious local kill.
func schedulerChannelTimeoutMarginMs() time.Duration {
	ms := 2000
	if v := os.Getenv("SCHEDULER_CHANNEL_TIMEOUT_MARGIN_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ms = parsed
		}
	}
	return time.Duration(ms) * time.Millisecond
}

// pausedEventTimeout bounds the blocking EXECUTION_PAUSED call.
// maxPauseDurationMs is THIS pause cycle's own deadline (CLAUDE.md §4.7,
// as dispatched — or as last updated by a previous RESUME_EXECUTION,
// though V1 never changes it mid-trace).
func pausedEventTimeout(maxPauseDurationMs int64) time.Duration {
	if maxPauseDurationMs < 0 {
		maxPauseDurationMs = 0
	}
	return time.Duration(maxPauseDurationMs)*time.Millisecond + schedulerChannelTimeoutMarginMs()
}

// ExecutionPausedEvent is CLAUDE.md §7.6's EXECUTION_PAUSED event shape.
type ExecutionPausedEvent struct {
	Event            string  `json:"event"`
	TraceID          string  `json:"trace_id"`
	ReservationID    string  `json:"reservation_id"`
	PauseID          string  `json:"pause_id"`
	ActionName       string  `json:"action_name"`
	ExecutionPhase   string  `json:"execution_phase"`
	EnergyConsumedJ  float64 `json:"energy_consumed_j"`
	PauseRequestedAt float64 `json:"pause_requested_at"`
	PauseEffectiveAt float64 `json:"pause_effective_at"`
	FreezeLatencyMs  float64 `json:"freeze_latency_ms"`
}

// SchedulerCommand is CLAUDE.md §6.6's RESUME_EXECUTION / KILL_EXECUTION
// command shape (the union of both; only the fields relevant to
// Command are populated by the scheduler).
type SchedulerCommand struct {
	Command                string  `json:"command"`
	TraceID                string  `json:"trace_id"`
	ReservationID          string  `json:"reservation_id"`
	PauseID                string  `json:"pause_id"`
	NewExecutionThresholdJ float64 `json:"new_execution_threshold_j,omitempty"`
	Reason                 string  `json:"reason,omitempty"`
}

// newPauseID generates a unique pause_id (CLAUDE.md §2). Uses
// crypto/rand directly rather than pulling in a UUID dependency (this
// module pins its dependency set — see go.mod, testify v1.3.0) — 16
// random bytes give a collision probability negligible for this
// process's lifetime.
func newPauseID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is exceedingly rare (would indicate a
		// broken kernel entropy source); degrade to a timestamp-based ID
		// rather than aborting the whole pause cycle over it.
		log.Printf("[pause] crypto/rand failed, falling back to a timestamp-based pause_id: %v", err)
		return fmt.Sprintf("pause-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("pause-%x", buf)
}

// postExecutionPaused sends EXECUTION_PAUSED and BLOCKS for the
// scheduler's decision (§7.5 step 7). A non-nil error means the
// scheduler could not be reached or answered with something
// undecodable — the caller (energyMonitor.go's runPauseCycle) treats
// that as a reason to kill locally: resuming without ANY confirmed
// command would break CLAUDE.md §4.3's invariant
// (resume_allowed(pause_id) => extension_success(pause_id)), and this
// runtime has no way to satisfy that invariant if it cannot even reach
// the scheduler.
func postExecutionPaused(event ExecutionPausedEvent, maxPauseDurationMs int64) (*SchedulerCommand, error) {
	body, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal EXECUTION_PAUSED event: %w", err)
	}

	client := &http.Client{Timeout: pausedEventTimeout(maxPauseDurationMs)}
	resp, err := client.Post(schedulerEventsEndpoint(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST EXECUTION_PAUSED: %w", err)
	}
	defer resp.Body.Close()

	var command SchedulerCommand
	if err := json.NewDecoder(resp.Body).Decode(&command); err != nil {
		return nil, fmt.Errorf("decode scheduler command: %w", err)
	}
	return &command, nil
}

// postExecutionKilled sends EXECUTION_KILLED fire-and-forget (CLAUDE.md
// §3.1: must never block the /run response). Errors are only logged —
// there is nothing more useful to do with a lost delivery than what's
// already logged locally in runHandler.go/energyMonitor.go, and blocking
// or retrying here would reintroduce exactly the round-trip §3.1
// forbids.
func postExecutionKilled(event ExecutionKilledEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("[energy_monitor] failed to marshal EXECUTION_KILLED event for the scheduler channel: %v", err)
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(schedulerEventsEndpoint(), "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[energy_monitor] failed to POST EXECUTION_KILLED to the scheduler channel: %v", err)
		return
	}
	defer resp.Body.Close()
}
