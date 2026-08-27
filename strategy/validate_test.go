package strategy_test

import (
	"errors"
	"testing"

	"github.com/gopacket/gopacket"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"
	"github.com/getlantern/geneva/triggers"
)

func TestValidateRejectsInvalidASTs(t *testing.T) {
	t.Parallel()

	trigger, err := triggers.NewTCPTrigger("flags", "S", 0)
	if err != nil {
		t.Fatal(err)
	}
	validTree := func(action actions.Action) *actions.ActionTree {
		return &actions.ActionTree{Trigger: trigger, RootAction: action}
	}

	cycle := &actions.DuplicateAction{Right: &actions.SendAction{}}
	cycle.Left = cycle

	tests := []struct {
		name     string
		strategy *strategy.Strategy
	}{
		{name: "nil strategy", strategy: nil},
		{name: "nil tree", strategy: &strategy.Strategy{Outbound: strategy.Forest{nil}}},
		{name: "nil trigger", strategy: &strategy.Strategy{Outbound: strategy.Forest{{RootAction: &actions.SendAction{}}}}},
		// Note: a tree with a nil RootAction is valid: canonical Geneva allows trigger-only
		// passthrough trees such as "[TCP:flags:A]-|".
		{
			name: "inbound branch",
			strategy: &strategy.Strategy{Inbound: strategy.Forest{validTree(&actions.DuplicateAction{
				Left: &actions.SendAction{}, Right: &actions.SendAction{},
			})}},
		},
		{name: "action cycle", strategy: &strategy.Strategy{Outbound: strategy.Forest{validTree(cycle)}}},
		{name: "unsupported action", strategy: &strategy.Strategy{Outbound: strategy.Forest{validTree(unknownAction{})}}},
		// uncomparableAction is passed by value and contains a slice, so it cannot be used
		// as a map key. Validate must return an error rather than panic.
		{name: "uncomparable action", strategy: &strategy.Strategy{Outbound: strategy.Forest{validTree(uncomparableAction{})}}},
		{name: "unconfigured fragment", strategy: &strategy.Strategy{Outbound: strategy.Forest{validTree(&actions.FragmentAction{})}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := strategy.Validate(tc.strategy)
			if !errors.Is(err, strategy.ErrInvalidStrategy) {
				t.Errorf("Validate() error = %v, expected ErrInvalidStrategy", err)
			}
		})
	}
}

func TestValidateBoundsGenomeSize(t *testing.T) {
	t.Parallel()

	trigger, err := triggers.NewTCPTrigger("flags", "S", 0)
	if err != nil {
		t.Fatal(err)
	}
	forest := make(strategy.Forest, strategy.MaxTreesPerForest+1)
	for i := range forest {
		forest[i] = &actions.ActionTree{Trigger: trigger, RootAction: &actions.SendAction{}}
	}

	err = strategy.Validate(&strategy.Strategy{Outbound: forest})
	if !errors.Is(err, strategy.ErrInvalidStrategy) {
		t.Errorf("Validate() error = %v, expected ErrInvalidStrategy", err)
	}
}

func TestParseStrategyRejectsInvalidGenomes(t *testing.T) {
	t.Parallel()

	tests := []string{
		`[UDP:dport:53]-drop-| \/`,
		`[TCP:dport:443:1:extra]-drop-| \/`,
		`[TCP:dport:not-a-number]-drop-| \/`,
		`[TCP:flags:S]-fragment{TCP:-2:true}-| \/`,
		`[TCP:flags:S]-fragment{UDP:1:true}-| \/`,
	}
	for _, dna := range tests {
		t.Run(dna, func(t *testing.T) {
			t.Parallel()
			if _, err := strategy.ParseStrategy(dna); err == nil {
				t.Errorf("ParseStrategy(%q) accepted invalid DNA", dna)
			}
		})
	}
}

type unknownAction struct{}

func (unknownAction) Apply(gopacket.Packet) ([]gopacket.Packet, error) { return nil, nil }
func (unknownAction) String() string                                   { return "unknown" }

// uncomparableAction is a non-pointer struct containing a slice, making the Action interface
// value it produces non-comparable and therefore unusable as a map key.
type uncomparableAction struct {
	payload []int //nolint:unused // present specifically to make the struct non-comparable
}

func (uncomparableAction) Apply(gopacket.Packet) ([]gopacket.Packet, error) { return nil, nil }
func (uncomparableAction) String() string                                   { return "uncomparable" }
