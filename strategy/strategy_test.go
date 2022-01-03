package strategy_test

import (
	"fmt"
	"testing"

	"github.com/getlantern/geneva/strategy"
)

func TestFullStrategy(t *testing.T) {
	str := `[TCP:flags:SA]-duplicate(send,send)-| \/ [TCP:flags:S]-send-|`
	st, err := strategy.ParseStrategy(str)
	if err != nil {
		t.Fatalf("ParseStrategy() got an error: %v", err)
	}

	if len(st.Inbound) != 1 {
		t.Errorf("strategy should have 1 inbound action tree, but has %d", len(st.Inbound))
	}

	if len(st.Outbound) != 1 {
		t.Errorf("strategy should have 1 outbound action tree, but has %d", len(st.Outbound))
	}

	t.Log(st)
}

func TestStrategyMultipleActionTrees(t *testing.T) {
	str := `
[TCP:flags:SA]-duplicate(send,send)-|
[TCP:flags:PA]-duplicate(duplicate(send,drop),send)-|
\/
[TCP:flags:S]-send-|`
	st, err := strategy.ParseStrategy(str)
	if err != nil {
		t.Fatalf("ParseStrategy() got an error: %v", err)
	}

	if len(st.Inbound) != 2 {
		t.Errorf("strategy should have 2 inbound action trees, but has %d", len(st.Inbound))
	}

	if len(st.Outbound) != 1 {
		t.Errorf("strategy should have 2 outbound action trees, but has %d", len(st.Outbound))
	}
	t.Log(st)
}

func ExampleParseStrategy() {
	str := `
[TCP:flags:SA]-duplicate(send,send)-|
[TCP:flags:PA]-duplicate(duplicate(send,drop),send)-|
\/
[TCP:flags:S]-send-|`

	s, _ := strategy.ParseStrategy(str)

	fmt.Printf("%s", s)
	// Output: [TCP:flags:SA]-duplicate(send,send)-| [TCP:flags:PA]-duplicate(duplicate(send,drop),send)-| \/ [TCP:flags:S]-send-|
}
