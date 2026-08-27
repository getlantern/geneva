package actions_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/common"
	"github.com/getlantern/geneva/internal/scanner"
)

// TestActionlessActionTree ports the canonical behavior that an action tree may omit its action
// entirely ("[trigger]-|"); such trees parse, serialize, and pass packets through unharmed.
func TestActionlessActionTree(t *testing.T) {
	tree, err := actions.ParseActionTree(scanner.NewScanner("[IP:ttl:64]-|"))
	if err != nil {
		t.Fatalf("ParseActionTree() got an error: %v", err)
	}

	if tree.RootAction != nil {
		t.Fatalf("expected nil root action, got %T", tree.RootAction)
	}

	if got := tree.String(); got != "[IP:ttl:64]-|" {
		t.Fatalf("String() = %q, expected %q", got, "[IP:ttl:64]-|")
	}

	packet := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	result, err := tree.Apply(packet)
	if err != nil {
		t.Fatalf("Apply() got an error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("Apply() returned %d packets; a passthrough tree returns the packet unharmed", len(result))
	}
	if !bytes.Equal(result[0].Data(), packet.Data()) {
		t.Fatal("passthrough tree modified the packet")
	}
}

var (
	ping = []byte{
		0x00, 0x0d, 0xb9, 0x4d, 0x18, 0xfd, 0x78, 0x31, 0xc1, 0xbb, 0xd2, 0x1e, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x54, 0x97, 0x67, 0x00, 0x00, 0x40, 0x01, 0x5d, 0xc0, 0xc0, 0xa8,
		0x02, 0x30, 0xc0, 0xa8, 0x02, 0x01, 0x08, 0x00, 0x13, 0x66, 0xed, 0xba, 0x00, 0x00,
		0x61, 0xba, 0x3a, 0x41, 0x00, 0x0d, 0x6f, 0xd3, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}

	sshWithLinkLayer = []byte{
		0xf4, 0xd4, 0x88, 0x64, 0xe3, 0x2d, 0x00, 0xd, 0xb9, 0x4d, 0x18, 0xfd, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x49, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xb5, 0x2d, 0xc0, 0xa8,
		0x02, 0x30, 0xc0, 0xa8, 0x02, 0x01, 0xee, 0x3a, 0x00, 0x16, 0x6b, 0x8b, 0xad, 0x49,
		0x9f, 0x7b, 0x50, 0xae, 0x80, 0x18, 0x08, 0x0a, 0x61, 0x41, 0x00, 0x00, 0x01, 0x01,
		0x08, 0x0a, 0x8b, 0xc1, 0xd9, 0x53, 0x28, 0xbf, 0x41, 0x06, 0x53, 0x53, 0x48, 0x2d,
		0x32, 0x2e, 0x30, 0x2d, 0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f, 0x38, 0x2e,
		0x31, 0x0d, 0x0a,
	}
	ssh = sshWithLinkLayer[14:]
)

func TestIPv4HeaderChecksum(t *testing.T) {
	t.Parallel()
	// This comes straight from https://en.wikipedia.org/wiki/IPv4_header_checksum
	header := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
		0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
	}
	expected := uint16(0xb861)

	chksum := common.CalculateIPv4Checksum(header)
	if chksum != expected {
		t.Fatalf("expected %#04x, got %#04x", expected, chksum)
	}
}

func TestSendAction(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

	tests := []string{
		"fragment{IP:10:true}",
		"fragment{TCP:10:true}(,drop)",
		"fragment{IP:10:true}(duplicate(,),)",
		"fragment{IP:10:false}(duplicate(,),)",
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("%q", tc), func(t *testing.T) {
			t.Parallel()
			l := scanner.NewScanner(tc)
			_, err := actions.ParseAction(l)
			if err != nil {
				t.Fatalf("ParseAction() got an error: %v", err)
			}
		})
	}
}

func TestDuplicateAction(t *testing.T) {
	t.Parallel()

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
			t.Fatalf(
				"packet %d length: expected %d, got %d",
				i,
				len(ssh),
				len(p.Data()),
			)
		}

		pData := p.Data()
		for j, b := range ssh {
			if b != pData[j] {
				t.Fatalf(
					"packet %d differs at byte %d (expected %#x, got %#x)",
					i,
					j,
					b,
					pData[j],
				)
			}
		}
	}
}

type ipFragmentResult struct {
	frag          gopacket.Packet
	moreFragments layers.IPv4Flag
	fragOffset    uint16
	ipPayloadLen  uint16
}

//nolint:thelper
func VerifyIPFragment(
	t *testing.T,
	originalChecksum uint16,
	fragIndex int,
	result ipFragmentResult,
) {
	packetDumpLogged := false

	// this is just so that we only print out the packet dump once--instead of every time an
	// error occurs--and only if we actually encounter an error.
	dump := func() {
		if !packetDumpLogged {
			t.Log(result.frag.Dump())

			packetDumpLogged = true
		}
	}

	if l := result.frag.ErrorLayer(); l != nil {
		dump()
		t.Fatalf("failed to decode fragment %d: %v", fragIndex, l.Error())
	}

	ipLayer, ok := result.frag.NetworkLayer().(*layers.IPv4)
	if !ok {
		t.Fatal("type assertion failed")
	}

	if ipLayer.Checksum == originalChecksum {
		dump()
		t.Fatalf("checksum of fragment %d is the same as the original packet (0x%x)",
			fragIndex, ipLayer.Checksum)
	}

	payloadLen := ipLayer.Length - uint16(ipLayer.IHL*4)
	if payloadLen != result.ipPayloadLen {
		dump()
		t.Fatalf("fragment %d IP length header field: expected %d, got %d",
			fragIndex, result.ipPayloadLen, payloadLen)
	}

	if len(ipLayer.Payload) != int(result.ipPayloadLen) {
		dump()
		t.Fatalf("fragment %d IP payload length: expected %d, got %d",
			fragIndex, result.ipPayloadLen, len(ipLayer.Payload))
	}

	if len(ipLayer.Payload) != int(ipLayer.Length)-int(ipLayer.IHL*4) {
		dump()
		t.Fatalf("fragment %d total length mismatch: headers say %d, payload size is %d",
			fragIndex, int(ipLayer.Length)-int(ipLayer.IHL*4), len(ipLayer.Payload))
	}

	if mf := ipLayer.Flags & layers.IPv4MoreFragments; mf != result.moreFragments {
		dump()
		t.Fatalf("More Fragments flag of fragment %d: expected %d, got %d",
			fragIndex, result.moreFragments, mf)
	}

	if ipLayer.FragOffset != result.fragOffset {
		dump()
		t.Fatalf("fragment %d offset: expected %d, got %d",
			fragIndex, result.fragOffset, ipLayer.FragOffset)
	}

	if !actions.VerifyIPv4Checksum(ipLayer.Contents) {
		dump()
		t.Fatalf("fragment %d checksum is invalid: %#04x", fragIndex, ipLayer.Checksum)
	}
}

func TestFragmentActionIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pkt            []byte
		firstLayerType gopacket.LayerType
		fragSize       int
	}{
		{ssh, layers.LayerTypeIPv4, 1},
		{ssh, layers.LayerTypeIPv4, 3},
		{ssh, layers.LayerTypeIPv4, -1},
		{sshWithLinkLayer, layers.LayerTypeEthernet, 1},
		{sshWithLinkLayer, layers.LayerTypeEthernet, 2},
		{sshWithLinkLayer, layers.LayerTypeEthernet, -1},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(
			fmt.Sprintf("layer %s frag %d", tc.firstLayerType, tc.fragSize),
			func(t *testing.T) {
				t.Parallel()
				pkt := gopacket.NewPacket(
					tc.pkt,
					tc.firstLayerType,
					gopacket.Default,
				)

				pktIPv4Layer, ok := pkt.NetworkLayer().(*layers.IPv4)
				if !ok {
					t.Fatal("type assertion failed")
				}

				str := fmt.Sprintf("fragment{IP:%d:true}", tc.fragSize)

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

				var actualFragSize uint16
				if tc.fragSize == -1 {
					// IP frags are in words, and -1 means split the payload in
					// two
					actualFragSize = uint16(len(pktIPv4Layer.Payload)) / 8 / 2
				} else {
					actualFragSize = uint16(tc.fragSize)
				}

				expected := []ipFragmentResult{
					{
						result[0],
						1,
						0,
						actualFragSize * 8,
					},
					{
						result[1],
						0,
						actualFragSize,
						uint16(
							len(pktIPv4Layer.Payload),
						) - (actualFragSize * 8),
					},
				}

				for fragIdx, e := range expected {
					VerifyIPFragment(t, pktIPv4Layer.Checksum, fragIdx, e)
				}
			},
		)
	}
}

// Ported from upstream's fragment fallback test. A fragment action remains a
// branching action even when a zero offset cannot split the packet.
func TestFragmentActionIPZeroDuplicates(t *testing.T) {
	t.Parallel()

	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	action, err := actions.ParseAction(scanner.NewScanner("fragment{IP:0:false}"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := action.Apply(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d packets, expected 2", len(result))
	}
	if result[0] == result[1] {
		t.Fatal("fallback duplicate returned aliased packet objects")
	}
	if !bytes.Equal(result[0].Data(), result[1].Data()) {
		t.Fatal("fallback duplicate packets differ")
	}
}

type tcpFragmentResult struct {
	frag          gopacket.Packet
	ip4Len        uint16
	tcpPayloadLen uint16
}

func VerifyTCPFragment(t *testing.T, fragIndex int, result tcpFragmentResult) { //nolint:thelper
	packetDumpLogged := false

	// this is just so that we only print out the packet dump once--instead of every time an
	// error occurs--and only if we actually encounter an error.
	dump := func() {
		if !packetDumpLogged {
			t.Log(result.frag.Dump())

			packetDumpLogged = true
		}
	}

	if l := result.frag.ErrorLayer(); l != nil {
		dump()
		t.Fatalf("failed to decode fragment %d: %v", fragIndex, l.Error())
	}

	ipLayer, ok := result.frag.NetworkLayer().(*layers.IPv4)
	if !ok {
		t.Fatal("type assertion failed")
	}

	if !actions.VerifyIPv4Checksum(ipLayer.Contents) {
		dump()
		t.Fatalf("fragment %d checksum is invalid: %#04x", fragIndex, ipLayer.Checksum)
	}

	if ipLayer.Length != result.ip4Len {
		dump()
		t.Fatalf("fragment %d IP header length: expected %d, got %d",
			fragIndex, result.ip4Len, ipLayer.Length)
	}

	if len(ipLayer.Contents)+len(ipLayer.Payload) != int(ipLayer.Length) {
		dump()
		t.Fatalf("fragment %d IP total length: expected %d, got %d",
			fragIndex, ipLayer.Length, len(result.frag.Data()))
	}

	tcpLayer, ok := result.frag.TransportLayer().(*layers.TCP)
	if !ok {
		t.Fatal("type assertion failed")
	}

	if len(tcpLayer.Payload) != int(result.tcpPayloadLen) {
		dump()
		t.Fatalf("fragment %d TCP payload length: expected %d, got %d",
			fragIndex, result.tcpPayloadLen, len(tcpLayer.Payload))
	}
}

func TestFragmentActionTCP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pkt            []byte
		firstLayerType gopacket.LayerType
		fragSize       int
	}{
		{ssh, layers.LayerTypeIPv4, 8},
		{ssh, layers.LayerTypeIPv4, 13},
		{ssh, layers.LayerTypeIPv4, -1},
		{sshWithLinkLayer, layers.LayerTypeEthernet, 8},
		{sshWithLinkLayer, layers.LayerTypeEthernet, -1},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(
			fmt.Sprintf("layer %s frag %d", tc.firstLayerType, tc.fragSize),
			func(t *testing.T) {
				t.Parallel()
				pkt := gopacket.NewPacket(
					tc.pkt,
					tc.firstLayerType,
					gopacket.Default,
				)
				pktIPv4Layer, ok := pkt.NetworkLayer().(*layers.IPv4)
				if !ok {
					t.Fatal("type assertion failed")
				}

				pktTCPLayer, ok := pkt.TransportLayer().(*layers.TCP)
				if !ok {
					t.Fatal("type assertion failed")
				}

				str := fmt.Sprintf("fragment{TCP:%d:true}", tc.fragSize)

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

				var actualFragSize uint16
				if tc.fragSize == -1 {
					actualFragSize = uint16(len(pktTCPLayer.Payload)) / 2
				} else {
					actualFragSize = uint16(tc.fragSize)
				}

				expected := []tcpFragmentResult{
					{
						result[0],
						pktIPv4Layer.Length - uint16(
							len(pktTCPLayer.Payload),
						) + actualFragSize,
						actualFragSize,
					},
					{
						result[1],
						pktIPv4Layer.Length - actualFragSize,
						uint16(len(pktTCPLayer.Payload)) - actualFragSize,
					},
				}

				for i, e := range expected {
					t.Log("===== Original Packet =====")
					t.Log(pkt.Dump())
					VerifyTCPFragment(t, i, e)
				}
			},
		)
	}
}

// Ported from upstream's overlapping-segment tests. Overlap extends the first
// segment without changing where the second segment starts or its sequence.
func TestFragmentActionTCPOverlap(t *testing.T) {
	t.Parallel()

	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	originalTCP, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok {
		t.Fatal("test packet has no TCP layer")
	}
	originalPayload := append([]byte(nil), originalTCP.Payload...)

	action, err := actions.ParseAction(scanner.NewScanner("fragment{TCP:9:true:4}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := action.String(); got != "fragment{TCP:9:true:4}" {
		t.Fatalf("overlap was not serialized: got %q", got)
	}

	result, err := action.Apply(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("got %d segments, expected 2", len(result))
	}
	first := result[0].TransportLayer().(*layers.TCP)  //nolint:forcetypeassert
	second := result[1].TransportLayer().(*layers.TCP) //nolint:forcetypeassert
	if !bytes.Equal(first.Payload, originalPayload[:13]) {
		t.Errorf("first payload = %q, expected %q", first.Payload, originalPayload[:13])
	}
	if !bytes.Equal(second.Payload, originalPayload[9:]) {
		t.Errorf("second payload = %q, expected %q", second.Payload, originalPayload[9:])
	}
	if second.Seq != originalTCP.Seq+9 {
		t.Errorf("second sequence = %d, expected %d", second.Seq, originalTCP.Seq+9)
	}
}

func TestActionTreeSimple(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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

func TestActionCanonicalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected string
		original string
	}{
		{"[TCP:flags:S]-duplicate-|", "[TCP:flags:S]-duplicate(send,send)-|"},
		{"[TCP:flags:S]-duplicate(drop,)-|", "[TCP:flags:S]-duplicate(drop,send)-|"},
		{"[TCP:flags:S]-duplicate(,drop)-|", "[TCP:flags:S]-duplicate(send,drop)-|"},
		{
			"[TCP:flags:S]-duplicate(duplicate,)-|",
			"[TCP:flags:S]-duplicate(duplicate(send,send),send)-|",
		},
	}

	for i, tc := range tests {
		i, tc := i, tc

		t.Run(fmt.Sprintf(`"idx%d"`, i), func(t *testing.T) {
			t.Parallel()
			l := scanner.NewScanner(tc.original)
			a, err := actions.ParseActionTree(l)
			if err != nil {
				t.Fatalf("ParseActionTree() got an error: %v", err)
			}

			if a.String() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, a)
			}
		})
	}
}

// TestFragmentActionIPOversizedFragSize is a regression test for an over-large IP fragment
// size: the clamp previously never fired, so Apply panicked with a slice-bounds error.
func TestFragmentActionIPOversizedFragSize(t *testing.T) {
	packet := fragmentedIPPayloadPacket(t)

	for _, dna := range []string{"fragment{IP:8:true}", "fragment{IP:1000:true}"} {
		a, err := actions.ParseAction(scanner.NewScanner(dna))
		if err != nil {
			t.Fatalf("ParseAction(%q) got an error: %v", dna, err)
		}

		result, err := a.Apply(packet)
		if err != nil {
			t.Fatalf("Apply(%q) got an error: %v", dna, err)
		}
		if len(result) != 2 {
			t.Fatalf("Apply(%q) returned %d packets, expected 2", dna, len(result))
		}
	}
}

// TestFragmentActionTCPZeroFragSize documents canonical behavior: TCP fragment sizes are in
// bytes, so fragSize zero yields a header-only first segment and the untouched payload second.
func TestFragmentActionTCPZeroFragSize(t *testing.T) {
	packet := fragmentedIPPayloadPacket(t)

	a, err := actions.ParseAction(scanner.NewScanner("fragment{TCP:0:true}"))
	if err != nil {
		t.Fatal(err)
	}

	result, err := a.Apply(packet)
	if err != nil {
		t.Fatalf("Apply() got an error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("Apply() returned %d packets, expected 2", len(result))
	}

	first, ok := result[0].TransportLayer().(*layers.TCP)
	if !ok || first == nil {
		t.Fatal("first segment does not decode as TCP")
	}
	if len(first.Payload) != 0 {
		t.Errorf("first segment payload = %q, expected header-only", first.Payload)
	}

	second, ok := result[1].TransportLayer().(*layers.TCP)
	if !ok || second == nil {
		t.Fatal("second segment does not decode as TCP")
	}
	orig, _ := packet.TransportLayer().(*layers.TCP)
	if string(second.Payload) != string(orig.Payload) {
		t.Errorf("second segment payload = %q, expected original %q", second.Payload, orig.Payload)
	}
	if second.Seq != orig.Seq {
		t.Errorf("second segment seq = %d, expected original %d", second.Seq, orig.Seq)
	}
}

// fragmentedIPPayloadPacket builds a well-formed IPv4/TCP packet carrying exactly 20 bytes of
// payload (large enough that IP fragmentation cannot clamp to its midpoint).
func fragmentedIPPayloadPacket(t *testing.T) gopacket.Packet {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 2),
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		Seq:     100,
		Ack:     200,
		SYN:     true,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip,
		tcp,
		gopacket.Payload("0123456789abcdefghij"),
	)
	if err != nil {
		t.Fatal(err)
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
