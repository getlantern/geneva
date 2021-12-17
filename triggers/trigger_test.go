package triggers_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Crosse/geneva/internal/scanner"
	"github.com/Crosse/geneva/triggers"
)

func TestParseTrigger(t *testing.T) {
	tests := map[string]struct {
		trigger string
		want    reflect.Type
	}{
		"ip":  {"[IP:ttl:64]", reflect.TypeOf(&triggers.IPTrigger{})},
		"tcp": {"[TCP:dport:443]", reflect.TypeOf(&triggers.TCPTrigger{})},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
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
		"[TCP:sport:]",
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
		"[IP:ttl:]",
		"[IP:ttl:1",
		"[IP:ttl:1:",
		"[IP:ttl:1:]",
		"[IP:ttl:1:4",
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf(`"%s"`, tc), func(t *testing.T) {
			l := scanner.NewScanner(tc)
			_, err := triggers.ParseTrigger(l)
			if err == nil {
				t.Fatalf("ParseTrigger() did not return an error when it should have")
			}
		})
	}
}

func TestTriggersWithGas(t *testing.T) {
	tests := map[string]struct {
		trigger string
		want    int
	}{
		"ip":  {"[IP:ttl:64:2]", 2},
		"tcp": {"[TCP:dport:1337:4]", 4},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
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
	expected := "[TCP:sport:1337]"

	trigger, err := triggers.NewTCPTrigger("sport", "1337", 0)
	if err != nil {
		t.Fatalf("NewTCPTrigger() got an error: %v", err)
	}

	if trigger.String() != expected {
		t.Fatalf(`got "%s", expected "%s"`, trigger.String(), expected)
	}
}

func TestInvalidTCPField(t *testing.T) {
	if _, err := triggers.NewTCPTrigger("invalid", "12345", 0); err == nil {
		t.Fatalf("expected field error")
	}
}

func TestIPStringify(t *testing.T) {
	expected := "[IP:ttl:64]"

	trigger, err := triggers.NewIPTrigger("ttl", "64", 0)
	if err != nil {
		t.Fatalf("NewIPTrigger() got an error: %v", err)
	}

	if trigger.String() != expected {
		t.Fatalf(`got "%s", expected "%s"`, trigger.String(), expected)
	}
}

func TestInvalidIPField(t *testing.T) {
	if _, err := triggers.NewIPTrigger("invalid", "12345", 0); err == nil {
		t.Fatalf("expected field error")
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
