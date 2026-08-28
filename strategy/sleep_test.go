package strategy_test

import (
	"testing"
	"time"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"
	"github.com/getlantern/geneva/triggers"
)

// TestSleepStrategyRoundTrips confirms that a sleep action parses and validates in both the
// outbound and inbound forests (sleep is non-branching, so — unlike duplicate/fragment — it is
// valid inbound) and that it survives a String round-trip.
func TestSleepStrategyRoundTrips(t *testing.T) {
	t.Parallel()

	dna := `[TCP:flags:PA]-sleep{0.5}(tamper{TCP:flags:replace:R}(send),)-| \/ [TCP:flags:A]-sleep{1}-|`

	s, err := strategy.ParseStrategy(dna)
	if err != nil {
		t.Fatalf("ParseStrategy() error: %v", err)
	}

	if len(s.Outbound) != 1 || len(s.Inbound) != 1 {
		t.Fatalf("expected one tree per direction, got outbound=%d inbound=%d",
			len(s.Outbound), len(s.Inbound))
	}

	reparsed, err := strategy.ParseStrategy(s.String())
	if err != nil {
		t.Fatalf("re-parsing serialized strategy %q failed: %v", s.String(), err)
	}
	if reparsed.String() != s.String() {
		t.Fatalf("round-trip mismatch:\n  first: %q\n second: %q", s.String(), reparsed.String())
	}
}

// TestSleepNilChildValidates confirms that a sleep with a nil child validates: Apply and String
// treat a nil child as an elided send, and validation must agree (mutation/crossover can swap in
// nil passthrough subtrees).
func TestSleepNilChildValidates(t *testing.T) {
	t.Parallel()

	trigger, err := triggers.NewTCPTrigger("flags", "A", 0)
	if err != nil {
		t.Fatal(err)
	}

	s := &strategy.Strategy{
		Outbound: strategy.Forest{{
			Trigger:    trigger,
			RootAction: &actions.SleepAction{Duration: time.Second, Action: nil},
		}},
	}

	if err := strategy.Validate(s); err != nil {
		t.Fatalf("Validate() rejected a sleep with a nil child: %v", err)
	}
}
