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

import "testing"

// Required test #1 (CLAUDE.md hardening pass, follow-up verification):
// shouldMonitorEnergy's own gate is `energy.ExecutionThresholdJ > 0`
// (energyMonitor.go) — strictly greater than zero, so EXACTLY 0.0 is
// already, by the pre-existing convention, treated identically to a
// negative value: both disable enforcement. This directly locks in the
// exact comparison the exploration fix (core/scheduler.py forcing
// forward_execution_threshold_j = 0.0 for mode="exploration") depends
// on — no Go-side change was needed or made; this test exists so a
// future refactor of shouldMonitorEnergy (e.g. someone "simplifying" it
// to `>= 0`) cannot silently break that assumption.
func TestShouldMonitorEnergy_ZeroThresholdIsDisabled_SameAsNegative(t *testing.T) {
	cases := []struct {
		name      string
		threshold float64
		want      bool
	}{
		{"zero threshold disables monitoring", 0.0, false},
		{"negative threshold disables monitoring", -5.0, false},
		{"positive threshold enables monitoring", 1.0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			energy := &EnergyState{ExecutionThresholdJ: tc.threshold}
			got := shouldMonitorEnergy(energy)
			if got != tc.want {
				t.Errorf("shouldMonitorEnergy(ExecutionThresholdJ=%.1f) = %v, want %v", tc.threshold, got, tc.want)
			}
		})
	}
}

// nil energy (§7.5's third case — no energy_* nor __energy_state at
// all) must also disable monitoring, independent of the threshold value
// question above.
func TestShouldMonitorEnergy_NilEnergyStateIsDisabled(t *testing.T) {
	if shouldMonitorEnergy(nil) {
		t.Error("shouldMonitorEnergy(nil) = true, want false")
	}
}
