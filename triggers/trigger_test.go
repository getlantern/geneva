package triggers_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/getlantern/geneva/internal/scanner"
	"github.com/getlantern/geneva/triggers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
		{"load-valid", "load", "\xee\x3a\x00", true},
		{"load-invalid", "load", "\xee\x3a\x00\f7", false},
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
