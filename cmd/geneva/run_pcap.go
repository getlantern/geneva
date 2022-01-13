package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/getlantern/geneva"
	"github.com/getlantern/geneva/strategy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/urfave/cli/v2"
)

type FlowTable map[uint32]*Flow

type Flow struct {
	srcIP    net.IP
	dstIP    net.IP
	srcPort  uint16
	dstPort  uint16
	checksum uint32
}

func (f *Flow) DirectionEqual(flow *Flow) bool {
	return f.srcIP.Equal(flow.srcIP) &&
		f.dstIP.Equal(flow.dstIP) &&
		f.srcPort == flow.srcPort &&
		f.dstPort == flow.dstPort
}

func NewFlow(pkt gopacket.Packet) *Flow {
	flow := &Flow{}

	if ipv4, ok := pkt.NetworkLayer().(*layers.IPv4); ok && ipv4 != nil {
		flow.srcIP = ipv4.SrcIP
		flow.dstIP = ipv4.DstIP

		flow.checksum ^= binary.BigEndian.Uint32(ipv4.SrcIP)
		flow.checksum ^= binary.BigEndian.Uint32(ipv4.DstIP)
	} else if ipv6, ok := pkt.NetworkLayer().(*layers.IPv6); ok && ipv6 != nil {
		flow.srcIP = ipv6.SrcIP
		flow.dstIP = ipv6.DstIP

		flow.checksum ^= binary.BigEndian.Uint32(ipv6.SrcIP[0:4])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.SrcIP[4:8])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.SrcIP[8:12])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.SrcIP[12:])

		flow.checksum ^= binary.BigEndian.Uint32(ipv6.DstIP[0:4])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.DstIP[4:8])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.DstIP[8:12])
		flow.checksum ^= binary.BigEndian.Uint32(ipv6.DstIP[12:])
	}

	if tcp, ok := pkt.TransportLayer().(*layers.TCP); ok && tcp != nil {
		flow.srcPort = uint16(tcp.SrcPort)
		flow.dstPort = uint16(tcp.DstPort)

		flow.checksum ^= uint32(tcp.SrcPort)
		flow.checksum ^= uint32(tcp.DstPort)
	} else if udp, ok := pkt.TransportLayer().(*layers.UDP); ok && udp != nil {
		flow.srcPort = uint16(udp.SrcPort)
		flow.dstPort = uint16(udp.DstPort)

		flow.checksum ^= uint32(udp.SrcPort)
		flow.checksum ^= uint32(udp.DstPort)
	}

	return flow
}

func runPcap(c *cli.Context) error {
	input := c.String("input")
	output := c.String("output")
	strat := c.Args().First()

	s, err := geneva.NewStrategy(strat)
	if err != nil {
		return cli.Exit("invalid strategy", 1)
	}

	i, err := os.Open(input)
	if err != nil {
		return cli.Exit(fmt.Sprintf("error opening %s: %v", input, err), 1)
	}
	defer i.Close()

	r, err := pcapgo.NewReader(i)
	if err != nil {
		return cli.Exit(fmt.Sprintf("error reading %s: %v", input, err), 1)
	}

	source := gopacket.NewPacketSource(r, r.LinkType())

	flags := os.O_CREATE | os.O_WRONLY
	if !c.Bool("force") {
		flags |= os.O_EXCL
	}

	o, err := os.OpenFile(output, flags, 0o644)
	if err != nil {
		return cli.Exit(fmt.Sprintf("error opening %s: %v", input, err), 1)
	}
	defer o.Close()

	w := pcapgo.NewWriter(o)
	if err = w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return cli.Exit(fmt.Sprintf("while writing file header: %v", err), 1)
	}

	// Set up the world's worst flow tracker
	flows := make(FlowTable)

	count := 0
	outputCount := 0

	for pkt := range source.Packets() {
		flow := NewFlow(pkt)

		var (
			found     *Flow
			dir       strategy.Direction
			dirString string
			ok        bool
		)

		if found, ok = flows[flow.checksum]; !ok {
			flows[flow.checksum] = flow
			found = flow
		}

		if flow.DirectionEqual(found) {
			dir = strategy.DirectionOutbound
			dirString = "outbound"
		} else {
			dir = strategy.DirectionInbound
			dirString = " inbound"
		}

		fmt.Printf("[%4d] %s:%d -> %s:%d (%s): ",
			count,
			pkt.NetworkLayer().(*layers.IPv4).SrcIP,
			pkt.TransportLayer().(*layers.TCP).SrcPort,
			pkt.NetworkLayer().(*layers.IPv4).DstIP,
			pkt.TransportLayer().(*layers.TCP).DstPort,
			dirString)

		result, err := s.Apply(pkt, dir)
		if err != nil {
			return cli.Exit(fmt.Sprintf("error applying strategy: %v", err), 1)
		}

		fmt.Printf("=> %d packet(s)\n", len(result))

		for i, p := range result {
			fmt.Printf("\toutput %d: [caplen: %d, len: %d, datalen: %d]\n",
				i,
				pkt.Metadata().CaptureLength,
				pkt.Metadata().Length, len(p.Data()))

			if err = w.WritePacket(pkt.Metadata().CaptureInfo, p.Data()); err != nil {
				fmt.Fprintf(os.Stderr, "error writing packet: %v", err)
			}
			outputCount++
		}
		count++
	}

	fmt.Printf("Summary: read %d packets, wrote %d packets\n", count, outputCount)

	return nil
}
