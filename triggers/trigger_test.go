package triggers_test

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/getlantern/geneva/internal/scanner"
	"github.com/getlantern/geneva/triggers"
)

func TestParseTrigger(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		trigger string
		want    reflect.Type
	}{
		"ip":  {"[IP:ttl:64]", reflect.TypeOf(&triggers.IPTrigger{})},
		"tcp": {"[TCP:dport:443]", reflect.TypeOf(&triggers.TCPTrigger{})},
	}

	for name, tc := range tests {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l := scanner.NewScanner(tc.trigger)
			trigger, err := triggers.ParseTrigger(l)
			if err != nil {
				t.Fatalf("ParseTrigger() got an error: %v", err)
			}

			if reflect.TypeOf(trigger) != tc.want {
				t.Fatalf("expected type %s, got %T", tc.want, trigger)
			}
		})
	}
}

func TestParseTriggerFailure(t *testing.T) {
	t.Parallel()

	tests := []string{
		"[",
		"[TCP",
		"[TCP]",
		"[IP",
		"[IP]",
		"[asdf",
		"[asdf]",
		"[TCP:",
		"[TCP:]",
		"[TCP::]",
		"[TCP:::]",
		"[TCP:sport",
		"[TCP:sport]",
		"[TCP:sport:",
		"[TCP:sport:1",
		"[TCP:sport:1:",
		"[TCP:sport:1:]",
		"[TCP:sport:1:4",
		"[IP:",
		"[IP:]",
		"[IP::]",
		"[IP:::]",
		"[IP:ttl",
		"[IP:ttl]",
		"[IP:ttl:",
		"[IP:ttl:1",
		"[IP:ttl:1:",
		"[IP:ttl:1:]",
		"[IP:ttl:1:4",
	}

	for _, tc := range tests {
		tc := tc

		t.Run(fmt.Sprintf("%q", tc), func(t *testing.T) {
			t.Parallel()

			l := scanner.NewScanner(tc)
			_, err := triggers.ParseTrigger(l)
			if err == nil {
				t.Error(
					"ParseTrigger() did not return an error when it should have",
				)
			}
		})
	}
}

func TestTriggersWithGas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		trigger string
		want    int
	}{
		{"ip", "[IP:ttl:64:2]", 2},
		{"tcp", "[TCP:dport:1337:4]", 4},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l := scanner.NewScanner(tc.trigger)
			trigger, err := triggers.ParseTrigger(l)
			if err != nil {
				t.Fatalf("ParseTrigger() got an error: %v", err)
			}

			if trigger.Gas() != tc.want {
				t.Fatalf("Gas(): expected %d, got %d", tc.want, trigger.Gas())
			}
		})
	}
}

// These cases are ported from the canonical Python trigger tests. Positive
// gas is bounded-fire, zero is exhausted, and negative gas is a bomb that
// starts firing only after the configured number of matching packets.
func TestTriggerGasControlsMatches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dna     string
		matches []bool
	}{
		{name: "unlimited", dna: "[TCP:flags:SA]", matches: []bool{true, true, true}},
		{name: "one shot", dna: "[TCP:flags:SA:1]", matches: []bool{true, false, false}},
		{name: "exhausted", dna: "[TCP:flags:SA:0]", matches: []bool{false, false, false}},
		{name: "one match bomb", dna: "[TCP:flags:SA:-1]", matches: []bool{false, true, true}},
		{name: "three match bomb", dna: "[TCP:flags:SA:-3]", matches: []bool{false, false, false, true, true}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			trigger, err := triggers.ParseTrigger(scanner.NewScanner(tc.dna))
			if err != nil {
				t.Fatalf("ParseTrigger() got an error: %v", err)
			}

			for i, expected := range tc.matches {
				matched, err := trigger.Matches(tcpPacket(0x12))
				if err != nil {
					t.Fatalf("Matches() call %d got an error: %v", i, err)
				}
				if matched != expected {
					t.Errorf("Matches() call %d = %t, expected %t", i, matched, expected)
				}
			}

			if got := trigger.String(); got != tc.dna {
				t.Errorf("runtime gas changed serialized DNA: got %q, expected %q", got, tc.dna)
			}
		})
	}
}

func TestTriggerGasOnlyConsumesMatchingPackets(t *testing.T) {
	t.Parallel()

	trigger, err := triggers.ParseTrigger(scanner.NewScanner("[TCP:flags:SA:1]"))
	if err != nil {
		t.Fatal(err)
	}

	matched, err := trigger.Matches(tcpPacket(0x04))
	if err != nil || matched {
		t.Fatalf("nonmatching RST packet consumed or fired trigger: matched=%t err=%v", matched, err)
	}
	matched, err = trigger.Matches(tcpPacket(0x12))
	if err != nil || !matched {
		t.Fatalf("matching SYN+ACK packet did not receive remaining gas: matched=%t err=%v", matched, err)
	}
}

func TestTriggerGasIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	trigger, err := triggers.ParseTrigger(scanner.NewScanner("[TCP:flags:SA:25]"))
	if err != nil {
		t.Fatal(err)
	}

	var fired atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			matched, matchErr := trigger.Matches(tcpPacket(0x12))
			if matchErr != nil {
				t.Errorf("Matches() got an error: %v", matchErr)
				return
			}
			if matched {
				fired.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := fired.Load(); got != 25 {
		t.Errorf("bounded trigger fired %d times, expected 25", got)
	}
}

func TestTCPFlagsExactAndWildcardMatches(t *testing.T) {
	t.Parallel()

	exact, err := triggers.ParseTrigger(scanner.NewScanner("[TCP:flags:S]"))
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := triggers.ParseTrigger(scanner.NewScanner("[TCP:flags:S*]"))
	if err != nil {
		t.Fatal(err)
	}

	matched, err := exact.Matches(tcpPacket(0x12))
	if err != nil || matched {
		t.Fatalf("exact SYN trigger matched SYN+ACK: matched=%t err=%v", matched, err)
	}
	matched, err = wildcard.Matches(tcpPacket(0x12))
	if err != nil || !matched {
		t.Fatalf("wildcard SYN trigger did not match SYN+ACK: matched=%t err=%v", matched, err)
	}
}

func tcpPacket(flags byte) gopacket.Packet {
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

func TestTCPStringify(t *testing.T) {
	t.Parallel()

	expected := "[TCP:sport:1337]" // nolint:ifshort

	trigger, err := triggers.NewTCPTrigger("sport", "1337", 0)
	if err != nil {
		t.Fatalf("NewTCPTrigger() got an error: %v", err)
	}

	if trigger.String() != expected {
		t.Fatalf("got %q, expected %q", trigger.String(), expected)
	}
}

func TestInvalidTCPField(t *testing.T) {
	t.Parallel()

	if _, err := triggers.NewTCPTrigger("invalid", "12345", 0); err == nil {
		t.Fatalf("expected field error")
	}
}

func TestIPStringify(t *testing.T) {
	t.Parallel()

	expected := "[IP:ttl:64]" // nolint:ifshort

	trigger, err := triggers.NewIPTrigger("ttl", "64", 0)
	if err != nil {
		t.Fatalf("NewIPTrigger() got an error: %v", err)
	}

	if trigger.String() != expected {
		t.Fatalf("got %q, expected %q", trigger.String(), expected)
	}
}

func TestInvalidIPField(t *testing.T) {
	t.Parallel()

	if _, err := triggers.NewIPTrigger("invalid", "12345", 0); err == nil {
		t.Fatalf("expected field error")
	}
}

func TestIPTriggers(t *testing.T) {
	t.Parallel()

	ssh := []byte{
		0x45, 0x00, 0x00, 0x49, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xb5, 0x2d, 0xc0, 0xa8,
		0x02, 0x30, 0xc0, 0xa8, 0x02, 0x01, 0xee, 0x3a, 0x00, 0x16, 0x6b, 0x8b, 0xad, 0x49,
		0x9f, 0x7b, 0x50, 0xae, 0x80, 0x18, 0x08, 0x0a, 0x61, 0x41, 0x00, 0x00, 0x01, 0x01,
		0x08, 0x0a, 0x8b, 0xc1, 0xd9, 0x53, 0x28, 0xbf, 0x41, 0x06, 0x53, 0x53, 0x48, 0x2d,
		0x32, 0x2e, 0x30, 0x2d, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f, 0x38, 0x2e,
		0x31, 0x0d, 0x0a,
	}
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)

	tt := []struct {
		name        string
		field       string
		value       string
		shouldMatch bool
	}{
		{"version4", "version", "4", true},
		{"version6", "version", "6", false},
		{"ihl-valid", "ihl", "5", true},
		{"ihl-invalid", "ihl", "6", false},
		{"tos-valid", "tos", "0", true},
		{"tos-invalid", "tos", "1", false},
		{"len-valid", "len", fmt.Sprintf("%d", len(ssh)), true},
		{"len-invalid", "len", "1", false},
		{"id-valid", "id", "0", true},
		{"id-invalid", "id", "1", false},
		{"flags-valid-df", "flags", "DF", true},
		{"flags-valid-mf", "flags", "MF", false},
		{"flags-valid-evil", "flags", "evil", false},
		{"frag-valid", "frag", "0", true},
		{"frag-invalid", "frag", "1", false},
		{"ttl-valid", "ttl", "64", true},
		{"ttl-invalid", "ttl", "13", false},
		{"proto-valid", "proto", "6", true},
		{"proto-invalid", "proto", "17", false},
		{"chksum-valid", "chksum", "46381", true},
		{"chksum-valid-hex", "chksum", "0xb52d", true},
		{"chksum-invalid", "chksum", "7", false},
		{"src-valid", "src", "192.168.2.48", true},
		{"src-invalid", "src", "192.168.1.48", false},
		{"dst-valid", "dst", "192.168.2.1", true},
		{"dst-invalid", "dst", "192.168.1.3", false},
		{
			"load-valid",
			"load",
			"\xee\x3a\x00\x16\x6b\x8b\xad\x49\x9f\x7b\x50\xae\x80\x18\x08\x0a\x61\x41\x00\x00\x01\x01\x08\x0a\x8b\xc1\xd9\x53\x28\xbf\x41\x06\x53\x53\x48\x2d\x32\x2e\x30\x2d\x4f\x70\x65\x6e\x53\x53\x48\x5f\x38\x2e\x31\x0d\x0a",
			true,
		},
		{"load-invalid", "load", "\xee\x3a\x00\xf7", false},
	}

	for _, tc := range tt {
		tc := tc

		t.Run(fmt.Sprintf("%q", tc.name), func(t *testing.T) {
			t.Parallel()

			trigger, _ := triggers.NewIPTrigger(tc.field, tc.value, 0)
			if m, err := trigger.Matches(pkt); err != nil {
				t.Fatalf("trigger.Matches() got an error: %v", err)
			} else if m != tc.shouldMatch {
				t.Errorf("failed")
			}
		})
	}
}

func ExampleNewIPTrigger() {
	t, _ := triggers.NewIPTrigger("ttl", "64", 0)

	fmt.Printf("%s", t)
	// Output: [IP:ttl:64]
}

func ExampleNewTCPTrigger() {
	t, _ := triggers.NewTCPTrigger("flags", "SA", 0)

	fmt.Printf("%s", t)
	// Output: [TCP:flags:SA]
}

// TestGasConstructorsDistinguishZero checks that the WithGas constructors interpret gas exactly
// as given (zero never fires) and that GasConfigured distinguishes unlimited from configured.
func TestGasConstructorsDistinguishZero(t *testing.T) {
	t.Parallel()

	zero, err := triggers.NewTCPTriggerWithGas("flags", "SA", 0)
	if err != nil {
		t.Fatal(err)
	}
	if matched, _ := zero.Matches(tcpPacket(0x12)); matched {
		t.Error("zero-gas trigger fired")
	}
	if gas, ok := zero.GasConfigured(); !ok || gas != 0 {
		t.Errorf("zero-gas GasConfigured() = (%d, %t), expected (0, true)", gas, ok)
	}

	bomb, err := triggers.NewTCPTriggerWithGas("flags", "SA", -2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		matched, err := bomb.Matches(tcpPacket(0x12))
		if err != nil {
			t.Fatal(err)
		}
		if want := i >= 2; matched != want {
			t.Errorf("bomb Matches() call %d = %t, expected %t", i, matched, want)
		}
	}

	unlimited, err := triggers.NewTCPTrigger("flags", "SA", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := unlimited.GasConfigured(); ok {
		t.Error("legacy constructor with gas 0 should configure unlimited gas")
	}

	ipUnlimited, err := triggers.NewIPTrigger("ttl", "64", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ipUnlimited.GasConfigured(); ok {
		t.Error("legacy IP trigger with gas 0 should configure unlimited gas")
	}
}

// TestEmptyTriggerValues ports canonical Geneva's empty-value handling: "[tcp:load:]" matches
// packets with no payload and an empty option value is a presence trigger, while an empty value
// for any other field would be a permanently dead trigger and is rejected explicitly.
func TestEmptyTriggerValues(t *testing.T) {
	t.Parallel()

	rejected := []string{
		"[TCP:flags:]",
		"[TCP:dport:]",
		"[TCP:sport:]",
		"[TCP:seq:]",
		"[TCP:window:]",
		"[IP:flags:]",
		"[IP:ttl:]",
		"[IP:len:]",
	}
	for _, dna := range rejected {
		trigger, err := triggers.ParseTrigger(scanner.NewScanner(dna))
		if err == nil {
			t.Errorf("ParseTrigger(%q) = %s, expected an error for the empty value", dna, trigger)
			continue
		}
		if !strings.Contains(err.Error(), "empty trigger value") {
			t.Errorf("ParseTrigger(%q) error %q should mention the empty trigger value", dna, err)
		}
	}

	accepted := []string{
		"[TCP:load:]",
		"[IP:load:]",
		// An empty option value is a presence trigger and is legitimate for any option;
		// canonical Geneva ships strategies like "[tcp:options-sackok:]" and "[tcp:options-sack:]".
		"[TCP:options-sackok:]",
		"[TCP:options-nop:]",
		"[TCP:options-mss:]",
		"[TCP:options-wscale:]",
		"[TCP:options-sack:]",
		"[TCP:options-timestamp:]",
		// Non-empty option values with gas still parse.
		"[TCP:options-sack:4:4]",
	}
	for _, dna := range accepted {
		if _, err := triggers.ParseTrigger(scanner.NewScanner(dna)); err != nil {
			t.Errorf("ParseTrigger(%q) got an error: %v; empty payload values are valid", dna, err)
		}
	}

	loadTrigger, err := triggers.NewTCPTrigger("load", "", 0)
	if err != nil {
		t.Fatalf("NewTCPTrigger(load, \"\") got an error: %v", err)
	}

	if matched, err := loadTrigger.Matches(tcpPacket(0x10)); err != nil || !matched {
		t.Errorf("[TCP:load:] should match a packet with no payload (matched=%t, err=%v)", matched, err)
	}
	if matched, err := loadTrigger.Matches(tcpPacketWithPayload("hello")); err != nil || matched {
		t.Errorf("[TCP:load:] should not match a packet with a payload (matched=%t, err=%v)", matched, err)
	}
}

// tcpPacketWithPayload returns a TCP packet carrying the given ASCII payload.
func tcpPacketWithPayload(payload string) gopacket.Packet {
	base := tcpPacket(0x10).Data()
	data := make([]byte, len(base), len(base)+len(payload))
	copy(data, base)
	data = append(data, []byte(payload)...)

	// The TCP header ends at offset 40 (20 bytes IP + 20 bytes TCP); bump Total Length. The
	// length must fit the 16-bit field, so oversized payloads fail loudly instead of wrapping
	// into an invalid packet.
	if len(data) > 0xffff {
		panic(fmt.Sprintf("tcpPacketWithPayload: packet too large: %d bytes", len(data)))
	}
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))

	return gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
}
