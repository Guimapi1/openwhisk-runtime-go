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
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupFakeRAPLMaxFile points RAPL_PATH at a temp dir with a controlled
// max_energy_range_uj sibling file, so readRAPLMax() reads a known
// value rather than falling back to 1<<32.
func setupFakeRAPLMaxFile(t *testing.T, maxUJ int64) {
	dir := t.TempDir()
	os.Setenv("RAPL_PATH", filepath.Join(dir, "energy_uj"))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "max_energy_range_uj"), []byte(strconv.FormatInt(maxUJ, 10)), 0644,
	))
}

// 1. Regression test for a real incident found on cluster (see this
// file's own history / CLAUDE.md §0): deltaRAPLUJ() used to treat ANY
// end < start as a genuine register overflow, injecting the entire
// max_energy_range_uj into the computed delta — a trivial, non-
// monotonic read fluctuation (no relation to a real wraparound)
// produced a delta on the order of 260 000 J from a real consumption
// of a few tens of joules. Only a genuine overflow SIGNATURE (start
// close to the register's own ceiling) must trigger the full
// correction; any other end < start case must NOT.
func TestDeltaRAPLUJ_OnlyGenuineOverflowTriggersFullCorrection(t *testing.T) {
	const maxUJ = int64(262_144_000_000) // a realistic Intel RAPL package max_energy_range_uj
	setupFakeRAPLMaxFile(t, maxUJ)

	cases := []struct {
		name          string
		start, end    int64
		wantDelta     int64
		wantSafetyLog bool
	}{
		{
			name: "normal forward progress (no jitter)",
			start: 1_000_000_000, end: 1_000_050_000,
			wantDelta: 50_000, wantSafetyLog: false,
		},
		{
			name: "tiny negative jitter, end just barely < start",
			start: 1_000_000_000, end: 999_999_900,
			// NOT max-start+end (~262144000000J) -- must be treated as
			// an unreliable reading, not overflow.
			wantDelta: 0, wantSafetyLog: true,
		},
		{
			name: "small negative jitter, end well below start but NOT near zero",
			start: 1_000_000_000, end: 500_000_000,
			wantDelta: 0, wantSafetyLog: true,
		},
		{
			name: "end == start (no progress)",
			start: 1_000_000_000, end: 1_000_000_000,
			wantDelta: 0, wantSafetyLog: false, // handled by the end >= start branch, never reaches the overflow check
		},
		{
			name: "genuine wraparound: end near zero after passing max",
			start: maxUJ - 1_000_000, end: 50_000,
			wantDelta: 1_050_000, wantSafetyLog: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			log.SetOutput(&logBuf)
			defer log.SetOutput(os.Stderr)

			delta := deltaRAPLUJ(c.start, c.end)
			assert.Equal(t, c.wantDelta, delta, "start=%d end=%d", c.start, c.end)

			logged := logBuf.String()
			if c.wantSafetyLog {
				assert.Contains(t, logged, "[safety] ", "must log a critical safety event")
				assert.Contains(t, logged, "RAPL_NON_MONOTONIC_READING")
			} else {
				assert.NotContains(t, logged, "RAPL_NON_MONOTONIC_READING",
					"a genuine overflow or normal progress must not log this event")
			}
		})
	}
}

// 2. The proximity threshold is applied precisely, not loosely — a
// case just above vs. just below the threshold on either side.
func TestDeltaRAPLUJ_ProximityThresholdAppliedPrecisely(t *testing.T) {
	const maxUJ = int64(262_144_000_000)
	setupFakeRAPLMaxFile(t, maxUJ)
	os.Setenv("RAPL_OVERFLOW_PROXIMITY_THRESHOLD", "0.9")
	defer os.Unsetenv("RAPL_OVERFLOW_PROXIMITY_THRESHOLD")

	threshold := int64(float64(maxUJ) * 0.9) // 235_929_600_000

	t.Run("start just ABOVE threshold: treated as genuine overflow", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stderr)

		start := threshold + 1_000
		end := int64(500)
		delta := deltaRAPLUJ(start, end)

		assert.Equal(t, (maxUJ-start)+end, delta)
		assert.NotContains(t, logBuf.String(), "RAPL_NON_MONOTONIC_READING")
	})

	t.Run("start just BELOW threshold: treated as non-monotonic, not overflow", func(t *testing.T) {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stderr)

		start := threshold - 1_000
		end := int64(500)
		delta := deltaRAPLUJ(start, end)

		assert.Equal(t, int64(0), delta)
		assert.Contains(t, logBuf.String(), "RAPL_NON_MONOTONIC_READING")
	})
}
