package actions_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/internal/scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	ping []byte = []byte{
		0x00, 0x0d, 0xb9, 0x4d, 0x18, 0xfd, 0x78, 0x31, 0xc1, 0xbb, 0xd2, 0x1e, 0x08, 0x00, 0x45, 0x00, 0x00,
		0x54, 0x97, 0x67, 0x00, 0x00, 0x40, 0x01, 0x5d, 0xc0, 0xc0, 0xa8, 0x02, 0x30, 0xc0, 0xa8, 0x02, 0x01,
		0x08, 0x00, 0x13, 0x66, 0xed, 0xba, 0x00, 0x00, 0x61, 0xba, 0x3a, 0x41, 0x00, 0x0d, 0x6f, 0xd3, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
		0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}

	ssh []byte = []byte{
		0x45, 0x00, 0x00, 0x49, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xb5, 0x2d, 0xc0, 0xa8, 0x02, 0x30, 0xc0,
		0xa8, 0x02, 0x01, 0xee, 0x3a, 0x00, 0x16, 0x6b, 0x8b, 0xad, 0x49, 0x9f, 0x7b, 0x50, 0xae, 0x80, 0x18,
		0x08, 0x0a, 0x61, 0x41, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x8b, 0xc1, 0xd9, 0x53, 0x28, 0xbf, 0x41,
		0x06, 0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f,
		0x38, 0x2e, 0x31, 0x0d, 0x0a,
	}
)

func TestIPv4HeaderChecksum(t *testing.T) {
	// This comes straight from https://en.wikipedia.org/wiki/IPv4_header_checksum
	header := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0,
		0xa8, 0x00, 0xc7,
	}
	expected := uint16(0xb861)

	chksum := actions.ComputeIPv4Checksum(header)
	if chksum != expected {
		t.Fatalf("expected %#04x, got %#04x", expected, chksum)
	}

	if val := binary.BigEndian.Uint16(header[10:]); val != expected {
		t.Fatalf("expected %#04x in header, got %#04x", expected, val)
	}

	if !actions.VerifyIPv4Checksum(header) {
		t.Fatal("checksum validation failed")
	}
}

func TestSendAction(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	a := actions.SendAction{}
	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatalf("no packet returned")
	}

	if result[0] != pkt {
		t.Errorf("returned packet reference is different than the passed-in packet")
	}

	pktData := pkt.Data()
	for i, b := range result[0].Data() {
		if b != pktData[i] {
			t.Fatalf("returned packet is different than the passed-in packet")
		}
	}
}

func TestDropAction(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	a := actions.DropAction{}
	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 0 {
		t.Fatalf("drop action should never return anything")
	}
}

func TestSimpleDuplicateAction(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	l := scanner.NewScanner("duplicate(send,send)")
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(result))
	}
}

func TestDuplicateActionDrop(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	l := scanner.NewScanner("duplicate(send,drop)")
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result))
	}
}

func TestParseFragmentAction(t *testing.T) {
	tests := []string{
		"fragment{IP:10:true}",
		"fragment{TCP:10:true}(,drop)",
		"fragment{UDP:10:true}(drop,)",
		"fragment{IP:10:true}(duplicate(,),)",
		"fragment{IP:10:false}(duplicate(,),)",
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf(`"%s"`, tc), func(t *testing.T) {
			l := scanner.NewScanner(tc)
			_, err := actions.ParseAction(l)
			if err != nil {
				t.Fatalf("ParseAction() got an error: %v", err)
			}
		})
	}
}

func TestDuplicateAction(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	l := scanner.NewScanner("duplicate(,)")
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, but got %d", len(result))
	}

	for i, p := range result {
		if p == nil {
			t.Fatalf("packet %d is nil", i)
		}
		if len(p.Data()) != len(ssh) {
			t.Fatalf("packet %d length: expected %d, got %d", i, len(ssh), len(p.Data()))
		}

		pData := p.Data()
		for j, b := range ssh {
			if b != pData[j] {
				t.Fatalf("packet %d differs at byte %d (expected %#x, got %#x)", i, j, b, pData[j])
			}
		}
	}
}

func TestFragmentActionIPCutInHalf(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	pktIPv4Layer := pkt.NetworkLayer().(*layers.IPv4)
	fragSize := -1

	str := fmt.Sprintf("fragment{IP:%d:true}", fragSize)

	l := scanner.NewScanner(str)
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, but got %d", len(result))
	}

	originalPayloadLen := len(pktIPv4Layer.Payload)
	payloadInWords := originalPayloadLen / 8

	firstFragLen := payloadInWords / 2

	secondFragOffset := firstFragLen
	secondFragLen := payloadInWords - firstFragLen

	layer := result[0].NetworkLayer().(*layers.IPv4)
	if layer.FragOffset != 0 {
		t.Errorf("fragment 1 offset: expected %d, got %d", 0, layer.FragOffset)
	}

	if len(layer.Payload) != firstFragLen*8 {
		t.Errorf("fragment 1 payload length: expected %d, got %d", firstFragLen*8, len(layer.Payload))
	}

	layer = result[1].NetworkLayer().(*layers.IPv4)
	if layer.FragOffset != uint16(secondFragOffset) {
		t.Errorf("fragment 2 offset: expected %d, got %d", secondFragOffset, layer.FragOffset)
	}

	if len(layer.Payload) != (secondFragLen*8)+(originalPayloadLen%8) {
		t.Errorf("fragment 1 payload length: expected %d, got %d", firstFragLen*8, len(layer.Payload))
	}
}

func TestFragmentActionIP(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	pktIPv4Layer := pkt.NetworkLayer().(*layers.IPv4)

	fragSize := uint16(1)
	str := fmt.Sprintf("fragment{IP:%d:true}", fragSize)

	l := scanner.NewScanner(str)
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, but got %d", len(result))
	}

	expected := []struct {
		packetDumpLogged bool
		frag             gopacket.Packet
		moreFragments    layers.IPv4Flag
		fragOffset       uint16
		payloadLen       uint16
	}{
		{
			false,
			result[0],
			1,
			0,
			fragSize * 8,
		},
		{
			false,
			result[1],
			0,
			fragSize,
			uint16(len(pktIPv4Layer.Payload)) - fragSize*8,
		},
	}

	for i, e := range expected {
		// this is just so that we only print out the packet dump once--instead of every time an error
		// occurs--and only if we actually encounter an error.
		dump := func() {
			if !e.packetDumpLogged {
				t.Log(e.frag.Dump())
				e.packetDumpLogged = true
			}
		}

		if l := e.frag.ErrorLayer(); l != nil {
			dump()
			t.Fatalf("failed to decode fragment %d: %v", i, l.Error())
		}

		layer := e.frag.NetworkLayer().(*layers.IPv4)
		if layer.Checksum == pktIPv4Layer.Checksum {
			dump()
			t.Errorf("checksum of fragment %d is the same as the original packet (0x%x)", i, layer.Checksum)
		}

		payloadLen := layer.Length - uint16(layer.IHL*4)
		if payloadLen != e.payloadLen {
			dump()
			t.Errorf("fragment %d length header field: expected %d, got %d", i, e.payloadLen, payloadLen)
		}

		if len(layer.Payload) != int(e.payloadLen) {
			dump()
			t.Errorf("fragment %d payload length: expected %d, got %d", i, e.payloadLen, len(layer.Payload))
		}

		if len(e.frag.Data()) != int(layer.Length) {
			dump()
			t.Errorf("fragment %d total length: expected %d, got %d", i, layer.Length, len(e.frag.Data()))
		}

		if mf := layer.Flags & layers.IPv4MoreFragments; mf != e.moreFragments {
			dump()
			t.Errorf("More Fragments flag of fragment %d: expected %d, got %d", i, e.moreFragments, mf)
		}

		if layer.FragOffset != e.fragOffset {
			dump()
			t.Errorf("fragment %d offset: expected %d, got %d", i, e.fragOffset, layer.FragOffset)
		}

		if !actions.VerifyIPv4Checksum(layer.Contents) {
			dump()
			t.Errorf("fragment %d checksum is invalid: %#04x", i, layer.Checksum)
		}
	}
}

func TestFragmentActionTCPCutInHalf(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	pktTCPLayer := pkt.TransportLayer().(*layers.TCP)

	fragSize := -1
	str := fmt.Sprintf("fragment{TCP:%d:true}", fragSize)

	l := scanner.NewScanner(str)
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, but got %d", len(result))
	}

	expected := []struct {
		frag          gopacket.Packet
		tcpPayloadLen uint16
	}{
		{
			result[0],
			uint16(len(pktTCPLayer.Payload) / 2),
		},
		{
			result[1],
			uint16(len(pktTCPLayer.Payload)) - uint16(len(pktTCPLayer.Payload)/2),
		},
	}

	for i, e := range expected {
		if l := e.frag.ErrorLayer(); l != nil {
			t.Fatalf("failed to decode fragment %d: %v", i, l.Error())
		}

		layer := e.frag.NetworkLayer().(*layers.IPv4)
		tcpLayer := e.frag.TransportLayer().(*layers.TCP)
		if len(tcpLayer.Payload) != int(e.tcpPayloadLen) {
			t.Fatalf("fragment %d TCP payload length: expected %d, got %d",
				i, e.tcpPayloadLen, len(tcpLayer.Payload))
		}

		if len(e.frag.Data()) != int(layer.Length) {
			t.Fatalf("fragment %d IP total length: expected %d, got %d", i, layer.Length, len(e.frag.Data()))
		}
	}
}
func TestFragmentActionTCP(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	pktIPv4Layer := pkt.NetworkLayer().(*layers.IPv4)
	pktTCPLayer := pkt.TransportLayer().(*layers.TCP)

	fragSize := uint16(8)
	str := fmt.Sprintf("fragment{TCP:%d:true}", fragSize)

	l := scanner.NewScanner(str)
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result, err := a.Apply(pkt)
	if err != nil {
		t.Fatalf("Apply() failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 packets, but got %d", len(result))
	}

	expected := []struct {
		packetDumpLogged bool
		frag             gopacket.Packet
		ip4Len           uint16
		tcpPayloadLen    uint16
		ipChecksum       uint16
	}{
		{
			false,
			result[0],
			pktIPv4Layer.Length - uint16(len(pktTCPLayer.Payload)) + fragSize,
			fragSize,
			0x6141,
		},
		{
			false,
			result[1],
			pktIPv4Layer.Length - fragSize,
			uint16(len(pktTCPLayer.Payload)) - fragSize,
			0,
		},
	}

	for i, e := range expected {
		// this is just so that we only print out the packet dump once--instead of every time an error
		// occurs--and only if we actually encounter an error.
		dump := func() {
			if !e.packetDumpLogged {
				t.Log("-------------------- ORIGINAL PACKET --------------------")
				t.Log(pkt.Dump())
				t.Log(pkt.String())
				t.Logf("---------------------- FRAGMENT %d ----------------------", i)
				t.Log(e.frag.Dump())
				e.packetDumpLogged = true
			}
		}

		if l := e.frag.ErrorLayer(); l != nil {
			dump()
			t.Fatalf("failed to decode fragment %d: %v", i, l.Error())
		}

		layer := e.frag.NetworkLayer().(*layers.IPv4)

		if !actions.VerifyIPv4Checksum(layer.Contents) {
			dump()
			t.Fatalf("fragment %d checksum is invalid: %#04x", i, layer.Checksum)
		}

		if layer.Length != e.ip4Len {
			dump()
			t.Fatalf("fragment %d packet length: expected %d, got %d", i, e.ip4Len, layer.Length)
		}

		tcpLayer := e.frag.TransportLayer().(*layers.TCP)
		if len(tcpLayer.Payload) != int(e.tcpPayloadLen) {
			dump()
			t.Fatalf("fragment %d TCP payload length: expected %d, got %d",
				i, e.tcpPayloadLen, len(tcpLayer.Payload))
		}

		if len(e.frag.Data()) != int(layer.Length) {
			dump()
			t.Fatalf("fragment %d IP total length: expected %d, got %d", i, layer.Length, len(e.frag.Data()))
		}

		// t.Log(e.frag.Dump())
		// t.Logf("fragment %d TCP checksum: %#x", i, tcpLayer.Checksum)
	}
}

func TestActionTreeSimple(t *testing.T) {
	str := "[TCP:flags:S]-duplicate(send,send)-|"
	l := scanner.NewScanner(str)
	at, err := actions.ParseActionTree(l)
	if err != nil {
		t.Fatalf("ParseActionTree() got an error: %v", err)
	}

	t.Logf("%s", at)

	if at.Trigger.Protocol() != "TCP" {
		t.Errorf("expected protocol TCP, got %s", at.Trigger.Protocol())
	}

	if at.Trigger.Field() != "flags" {
		t.Errorf("expected field 'flags', got '%s'", at.Trigger.Field())
	}

	if at.Trigger.Gas() != 0 {
		t.Errorf("expected gas value %d, got %d", 0, at.Trigger.Gas())
	}
}

func TestActionTreeNestedActions(t *testing.T) {
	str := "[TCP:flags:S]-duplicate(duplicate(drop,duplicate(send,drop)),send)-|"
	l := scanner.NewScanner(str)
	at, err := actions.ParseActionTree(l)
	if err != nil {
		t.Fatalf("ParseActionTree() got an error: %v", err)
	}

	t.Logf("%s", at)

	if at.Trigger.Protocol() != "TCP" {
		t.Errorf("expected protocol TCP, got %s", at.Trigger.Protocol())
	}

	if at.Trigger.Field() != "flags" {
		t.Errorf("expected field 'flags', got '%s'", at.Trigger.Field())
	}

	if at.Trigger.Gas() != 0 {
		t.Errorf("expected gas value %d, got %d", 0, at.Trigger.Gas())
	}
}

func TestActionSendElision(t *testing.T) {
	tests := []struct {
		elided   string
		expected string
	}{
		{"[TCP:flags:s]-duplicate(,)-|", "[TCP:flags:s]-duplicate(send,send)-|"},
		{"[TCP:flags:s]-duplicate(drop,)-|", "[TCP:flags:s]-duplicate(drop,send)-|"},
		{"[TCP:flags:s]-duplicate(,drop)-|", "[TCP:flags:s]-duplicate(send,drop)-|"},
		{"[TCP:flags:s]-duplicate(duplicate(,),)-|", "[TCP:flags:s]-duplicate(duplicate(send,send),send)-|"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf(`"%s"`, tc), func(t *testing.T) {
			l := scanner.NewScanner(tc.elided)
			a, err := actions.ParseActionTree(l)
			if err != nil {
				t.Fatalf("ParseActionTree() got an error: %v", err)
			}

			if a.String() != tc.expected {
				t.Errorf(`expected "%s", got "%s"`, tc.expected, a)
			}
		})
	}
}
