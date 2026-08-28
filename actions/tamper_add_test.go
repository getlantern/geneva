package actions

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/geneva/internal/scanner"
)

// TestTamperAddApply verifies that "add" mode increments a field's current value. testPkt has a
// TCP sequence number of 0xdeadbeef and an IP TTL of 128.
func TestTamperAddApply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rule   string
		verify func(*testing.T, gopacket.Packet)
	}{
		{
			name: "TCP sequence add",
			rule: "tamper{TCP:seq:add:1}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				tcp, ok := packet.TransportLayer().(*layers.TCP)
				require.True(t, ok)
				assert.Equal(t, uint32(0xdeadbef0), tcp.Seq)
			},
		},
		{
			name: "IPv4 TTL add",
			rule: "tamper{IP:ttl:add:1}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				ip, ok := packet.NetworkLayer().(*layers.IPv4)
				require.True(t, ok)
				assert.Equal(t, uint8(129), ip.TTL)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action, err := ParseTamperAction(scanner.NewScanner(tt.rule))
			require.NoError(t, err)

			result, err := action.Apply(testPkt())
			require.NoError(t, err)
			require.Len(t, result, 1)
			tt.verify(t, result[0])
		})
	}
}

func TestTamperAddRejectsUnsupportedFields(t *testing.T) {
	t.Parallel()

	rules := []string{
		"tamper{TCP:flags:add:1}", // bitmap, not numeric
		"tamper{TCP:load:add:1}",  // payload bytes
		"tamper{TCP:options-mss:add:1}",
		"tamper{IP:srcip:add:1}",   // address
		"tamper{IP:load:add:1}",    // payload bytes
		"tamper{IP:id:add:1}",      // field the tamperer does not write
		"tamper{TCP:seq:add}",      // add requires a value
		"tamper{TCP:seq:add:nope}", // value must be numeric
	}

	for _, rule := range rules {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()

			_, err := ParseTamperAction(scanner.NewScanner(rule))
			require.Error(t, err)
		})
	}
}

// TestTamperValuesCombineWraps confirms add mode masks to the field's bit size and wraps like
// canonical Geneva's Python integer arithmetic would after truncation.
func TestTamperValuesCombineWraps(t *testing.T) {
	t.Parallel()

	v := tamperValues{add: true, vUint: 2}
	assert.Equal(t, uint32(1), v.combine(0xffff, 16), "16-bit add should wrap")
	assert.Equal(t, uint32(0x1_0000_0001&0xffffffff), v.combine(0xffffffff, 32), "32-bit add should wrap")
}
