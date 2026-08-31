package geneva_test

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/geneva"
	"github.com/getlantern/geneva/strategy"
)

func TestNewStrategy(t *testing.T) {
	t.Parallel()

	for i, s := range geneva.Strategies {
		_, err := geneva.NewStrategy(s)
		assert.NoError(t, err, "failed to parse strategy %d %q", i, s)
	}
}

func TestAllStrategiesRoundTrip(t *testing.T) {
	t.Parallel()

	for i, dna := range geneva.Strategies {
		parsed, err := geneva.NewStrategy(dna)
		require.NoError(t, err, "failed to parse strategy %d %q", i, dna)
		require.NoError(t, geneva.Validate(parsed), "failed to validate strategy %d %q", i, dna)

		serialized := parsed.String()
		roundTripped, err := geneva.NewStrategy(serialized)
		require.NoError(t, err, "failed to reparse strategy %d %q", i, serialized)
		assert.Equal(t, serialized, roundTripped.String(), "strategy %d did not serialize canonically", i)
	}
}

func TestApplyAllStrategies(t *testing.T) {
	t.Parallel()

	for strategyIndex, dna := range geneva.Strategies {
		parsed, err := geneva.NewStrategy(dna)
		require.NoError(t, err, "failed to parse strategy %d %q", strategyIndex, dna)

		// Canonical Geneva's fragment and tamper tests build packets in memory.
		// Apply each bundled action tree directly so option-specific triggers do
		// not leave their action implementations untested.
		for treeIndex, tree := range parsed.Outbound {
			result, applyErr := tree.Apply(serverTCPPacket(t))
			require.NoError(t, applyErr, "strategy %d tree %d: %s", strategyIndex, treeIndex, dna)
			for packetIndex, packet := range result {
				require.NotNil(t, packet, "strategy %d tree %d packet %d", strategyIndex, treeIndex, packetIndex)
				require.NotEmpty(t, packet.Data(), "strategy %d tree %d packet %d", strategyIndex, treeIndex, packetIndex)
			}
		}
	}
}

func serverTCPPacket(t *testing.T) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 42424,
		Seq:     100,
		Ack:     200,
		PSH:     true,
		ACK:     true,
		Window:  65535,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip,
		tcp,
		gopacket.Payload("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
	)
	require.NoError(t, err)

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

// TestParseCanonicalEdgeCases ports the parse edge cases from the canonical Geneva
// tests/test_parse.py: quoted strategies, empty strategies, and trigger-only passthrough trees.
func TestParseCanonicalEdgeCases(t *testing.T) {
	t.Parallel()

	// Upstream test_quotes (their assertions call .strip(); this package serializes canonically
	// as "<outbound> \/ <inbound>", so an empty outbound forest yields a leading space).
	quoted, err := geneva.NewStrategy(`"\/"`)
	require.NoError(t, err)
	assert.Equal(t, ` \/ `, quoted.String())

	quoted, err = geneva.NewStrategy(`"\/ [TCP:flags:A]-drop-|"`)
	require.NoError(t, err)
	assert.Equal(t, ` \/ [TCP:flags:A]-drop-|`, quoted.String())

	// Upstream test_failures asserts an empty strategy parses and prints as " \/"
	empty, err := geneva.NewStrategy("")
	require.NoError(t, err)
	require.NoError(t, geneva.Validate(empty))
	assert.Equal(t, ` \/ `, empty.String())

	// Upstream EDGE_CASES that involve parsing shape only. The two tamper-value cases are not
	// asserted byte-for-byte because this package canonicalizes field and boolean casing during
	// serialization (as its parser accepts both forms).
	for _, dna := range []string{
		`[TCP:flags:A]-| \/`,
		`\/[TCP:flags:A]-|`,
		"[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \\/",
		`[IP:version:4]-| \/`,
		"[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \\/",
		"[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \\/",
	} {
		parsed, err := geneva.NewStrategy(dna)
		require.NoError(t, err, "dna %q", dna)
		require.NoError(t, geneva.Validate(parsed), "dna %q", dna)

		reparsed, err := geneva.NewStrategy(parsed.String())
		require.NoError(t, err, "serialized %q", parsed.String())
		assert.Equal(t, parsed.String(), reparsed.String())
	}
}

// TestActionlessTreePassthrough checks that a trigger-only tree yields the packet unharmed.
func TestActionlessTreePassthrough(t *testing.T) {
	t.Parallel()

	st, err := geneva.NewStrategy(`[TCP:sport:443]-|`)
	require.NoError(t, err)

	packet := serverTCPPacket(t)
	result, err := st.Apply(packet, strategy.DirectionOutbound)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, packet.Data(), result[0].Data())

	// A matched actionless tree counts as a match for forest semantics.
	forestMatched, err := st.Outbound[0].Matches(packet)
	require.NoError(t, err)
	assert.True(t, forestMatched)
}
