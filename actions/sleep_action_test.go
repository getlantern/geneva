package actions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/geneva/internal/scanner"
)

func TestParseSleepAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rule     string
		duration time.Duration
		child    string
		str      string
		wantErr  bool
	}{
		{
			name:     "whole seconds, implicit send child",
			rule:     "sleep{1}",
			duration: time.Second,
			child:    "send",
			str:      "sleep{1}",
		},
		{
			name:     "fractional seconds",
			rule:     "sleep{0.5}",
			duration: 500 * time.Millisecond,
			child:    "send",
			str:      "sleep{0.5}",
		},
		{
			name:     "zero duration",
			rule:     "sleep{0}",
			duration: 0,
			child:    "send",
			str:      "sleep{0}",
		},
		{
			name:     "explicit child action",
			rule:     "sleep{1}(drop)",
			duration: time.Second,
			child:    "drop",
			str:      "sleep{1}(drop)",
		},
		{
			name:    "non-numeric duration",
			rule:    "sleep{abc}",
			wantErr: true,
		},
		{
			name:    "negative duration",
			rule:    "sleep{-1}",
			wantErr: true,
		},
		{
			name:    "two children",
			rule:    "sleep{1}(drop,send)",
			wantErr: true,
		},
		{
			name:    "NaN duration",
			rule:    "sleep{NaN}",
			wantErr: true,
		},
		{
			name:    "infinite duration",
			rule:    "sleep{+Inf}",
			wantErr: true,
		},
		{
			name:    "overflowing duration",
			rule:    "sleep{1e400}",
			wantErr: true,
		},
		{
			name:    "duration too large for time.Duration",
			rule:    "sleep{100000000000}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action, err := ParseSleepAction(scanner.NewScanner(tt.rule))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			sleep, ok := action.(*SleepAction)
			require.True(t, ok, "expected *SleepAction, got %T", action)
			assert.Equal(t, tt.duration, sleep.Duration)
			assert.Equal(t, tt.child, sleep.Action.String())
			assert.Equal(t, tt.str, sleep.String())
		})
	}
}

func TestSleepActionApply(t *testing.T) {
	t.Parallel()

	t.Run("passes the packet to its child", func(t *testing.T) {
		t.Parallel()

		action, err := ParseSleepAction(scanner.NewScanner("sleep{0}"))
		require.NoError(t, err)

		result, err := action.Apply(testPkt())
		require.NoError(t, err)
		require.Len(t, result, 1, "sleep with a send child yields the packet unharmed")
	})

	t.Run("drop child discards the packet", func(t *testing.T) {
		t.Parallel()

		action, err := ParseSleepAction(scanner.NewScanner("sleep{0}(drop)"))
		require.NoError(t, err)

		result, err := action.Apply(testPkt())
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("nil child passes the packet through instead of panicking", func(t *testing.T) {
		t.Parallel()

		action := &SleepAction{Duration: 0, Action: nil}
		result, err := action.Apply(testPkt())
		require.NoError(t, err)
		require.Len(t, result, 1)
	})

	t.Run("actually delays for the configured duration", func(t *testing.T) {
		t.Parallel()

		action := &SleepAction{Duration: 20 * time.Millisecond, Action: &SendAction{}}
		start := time.Now()
		_, err := action.Apply(testPkt())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
	})
}
