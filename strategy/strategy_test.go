package strategy_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/getlantern/geneva/strategy"
)

func TestFullStrategy(t *testing.T) {
	t.Parallel()

	str := `[TCP:flags:SA]-duplicate(send,send)-| \/ [TCP:flags:S]-send-|`

	st, err := strategy.ParseStrategy(str)
	if err != nil {
		t.Fatalf("ParseStrategy() got an error: %v", err)
	}

	if len(st.Inbound) != 1 {
		t.Errorf("strategy should have 1 inbound action tree, but has %d", len(st.Inbound))
	}

	if len(st.Outbound) != 1 {
		t.Errorf(
			"strategy should have 1 outbound action tree, but has %d",
			len(st.Outbound),
		)
	}

	t.Log(st)
}

func TestStrategyMultipleActionTrees(t *testing.T) {
	t.Parallel()

	str := `
[TCP:flags:SA]-duplicate(send,send)-|
[TCP:flags:PA]-duplicate(duplicate(send,drop),send)-|
\/
[TCP:flags:S]-send-|`

	st, err := strategy.ParseStrategy(str)
	if err != nil {
		t.Fatalf("ParseStrategy() got an error: %v", err)
	}

	if len(st.Outbound) != 2 {
		t.Errorf(
			"strategy should have 2 outbound action trees, but has %d",
			len(st.Outbound),
		)
	}

	if len(st.Inbound) != 1 {
		t.Errorf("strategy should have 2 inbound action trees, but has %d", len(st.Inbound))
	}

	t.Log(st)
}

func TestParseStrategyRejectsInboundBranching(t *testing.T) {
	t.Parallel()

	tests := []string{
		`\/ [TCP:flags:S]-duplicate-|`,
		`\/ [TCP:flags:S]-fragment{TCP:-1:true}-|`,
		`\/ [TCP:flags:S]-tamper{TCP:flags:replace:R}(duplicate,)-|`,
	}
	for _, dna := range tests {
		t.Run(dna, func(t *testing.T) {
			t.Parallel()
			if _, err := strategy.ParseStrategy(dna); err == nil {
				t.Errorf("ParseStrategy(%q) accepted an inbound branching action", dna)
			}
		})
	}
}

func TestParseStrategyAllowsMultipleInboundTrees(t *testing.T) {
	t.Parallel()

	dna := `\/ [TCP:flags:S]-drop-| [TCP:flags:R]-tamper{IP:ttl:replace:32}-|`
	parsed, err := strategy.ParseStrategy(dna)
	if err != nil {
		t.Fatalf("ParseStrategy() got an error: %v", err)
	}
	if len(parsed.Inbound) != 2 {
		t.Fatalf("got %d inbound trees, expected 2", len(parsed.Inbound))
	}
}

// The canonical engine applies every matching tree to a fresh packet and
// returns one untouched packet only when no tree matches.
func TestApplyForestSemantics(t *testing.T) {
	t.Parallel()

	dna := `[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},)-| [TCP:flags:S]-send-| \/`
	parsed, err := strategy.ParseStrategy(dna)
	if err != nil {
		t.Fatal(err)
	}

	result, err := parsed.Apply(strategyTCPPacket(0x02), strategy.DirectionOutbound)
	if err != nil {
		t.Fatalf("Apply() got an error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("Apply() returned %d packets, expected 3", len(result))
	}
	want := []struct {
		rst bool
		syn bool
	}{{rst: true}, {syn: true}, {syn: true}}
	for i, packet := range result {
		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if !ok {
			t.Fatalf("packet %d has no TCP layer", i)
		}
		if tcp.RST != want[i].rst || tcp.SYN != want[i].syn {
			t.Errorf("packet %d flags: RST=%t SYN=%t, expected RST=%t SYN=%t",
				i, tcp.RST, tcp.SYN, want[i].rst, want[i].syn)
		}
	}

	noMatch, err := parsed.Apply(strategyTCPPacket(0x10), strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if len(noMatch) != 1 {
		t.Errorf("two nonmatching trees returned %d packets, expected one untouched packet", len(noMatch))
	}
}

func TestTriggerGasChangesStrategyApplication(t *testing.T) {
	t.Parallel()

	parsed, err := strategy.ParseStrategy(`[TCP:flags:S:1]-drop-| \/`)
	if err != nil {
		t.Fatal(err)
	}
	first, err := parsed.Apply(strategyTCPPacket(0x02), strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsed.Apply(strategyTCPPacket(0x02), strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 0 || len(second) != 1 {
		t.Errorf("one-shot drop returned packet counts %d then %d, expected 0 then 1", len(first), len(second))
	}
}

func strategyTCPPacket(flags byte) gopacket.Packet {
	data := make([]byte, 40)
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	data[8] = 64
	data[9] = byte(layers.IPProtocolTCP)
	copy(data[12:16], []byte{192, 0, 2, 1})
	copy(data[16:20], []byte{198, 51, 100, 2})
	binary.BigEndian.PutUint16(data[20:22], 12345)
	binary.BigEndian.PutUint16(data[22:24], 443)
	data[32] = 0x50
	data[33] = flags
	return gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
}

func ExampleParseStrategy() {
	str := `
[TCP:flags:SA]-duplicate(send,send)-|
[TCP:flags:PA]-duplicate(duplicate(send,drop),send)-|
\/
[TCP:flags:S]-send-|`

	s, _ := strategy.ParseStrategy(str)

	fmt.Printf("%s", s)
	// Output: [TCP:flags:SA]-duplicate-| [TCP:flags:PA]-duplicate(duplicate(,drop),)-| \/ [TCP:flags:S]-send-|
}
