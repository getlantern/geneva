package geneva_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func TestApplyAllStrategies(t *testing.T) {
	t.Skip("no input pcap file")

	t.Parallel()

	t.Log("reading pcap file")

	packets := []gopacket.Packet{}
	handle, err := pcap.OpenOffline("internal/testdata/input.pcap")
	require.NoError(t, err, "failed to open pcap file")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}

	t.Log("parsing strategies")

	strategies := []*strategy.Strategy{}
	for _, s := range geneva.Strategies {
		strat, err := geneva.NewStrategy(s)
		assert.NoError(t, err, "failed to parse strategy %q", s)
		strategies = append(strategies, strat)
	}

	t.Log("applying strategies")

	for _, s := range strategies {
		for _, p := range packets {
			p := gopacket.NewPacket(p.Data(), layers.LayerTypeEthernet, gopacket.Default)
			_, err := s.Apply(p, strategy.DirectionOutbound)
			assert.NoError(t, err, "strategy: %s\n%v", s, p)
		}
	}
}
