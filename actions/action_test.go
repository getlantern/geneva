package actions_test

import (
	"fmt"
	"testing"

	"github.com/Crosse/geneva/actions"
	"github.com/Crosse/geneva/internal/lexer"
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

func TestSendAction(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	a := actions.SendAction{}
	result := a.Apply(pkt)

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
	result := a.Apply(pkt)

	if len(result) != 0 {
		t.Fatalf("drop action should never return anything")
	}
}

func TestSimpleDuplicateAction(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	l := lexer.NewLexer("duplicate(send,send)")
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result := a.Apply(pkt)
	if len(result) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(result))
	}
}

func TestDuplicateActionDrop(t *testing.T) {
	pkt := gopacket.NewPacket(ping, layers.LayerTypeEthernet, gopacket.Default)

	l := lexer.NewLexer("duplicate(send,drop)")
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result := a.Apply(pkt)
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
			l := lexer.NewLexer(tc)
			_, err := actions.ParseAction(l)
			if err != nil {
				t.Fatalf("ParseAction() got an error: %v", err)
			}
		})
	}
}

func TestFragmentAction(t *testing.T) {
	pkt := gopacket.NewPacket(ssh, layers.LayerTypeIPv4, gopacket.Default)
	pktIPv4Layer := pkt.NetworkLayer().(*layers.IPv4)

	fragSize := uint16(8)
	str := fmt.Sprintf("fragment{IP:%d:true}", fragSize)

	l := lexer.NewLexer(str)
	a, err := actions.ParseAction(l)
	if err != nil {
		t.Fatalf("ParseAction() got an error: %v", err)
	}

	result := a.Apply(pkt)
	if len(result) != 2 {
		t.Fatalf("expected 2 packets got %d", len(result))
	}
	t.Log(result[0].Dump())
	t.Log(result[1].Dump())

	p1Logged, p2Logged := false, false

	layer := result[0].NetworkLayer().(*layers.IPv4)
	if layer.Checksum == pktIPv4Layer.Checksum {
		if !p1Logged {
			t.Log(result[0].Dump())
			p1Logged = true
		}
		t.Errorf("checksum of first fragment is the same as the original packet (0x%x)", layer.Checksum)
	}

	frag1ExpectedLen := uint16(pktIPv4Layer.IHL*4) + fragSize
	if layer.Length != frag1ExpectedLen {
		if !p1Logged {
			t.Log(result[0].Dump())
			p1Logged = true
		}
		t.Errorf("fragment 1 total length: expected %d, got %d", frag1ExpectedLen, layer.Length)
	}

	if layer.Flags&layers.IPv4MoreFragments == 0 {
		if !p1Logged {
			t.Log(result[0].Dump())
			p1Logged = true
		}
		t.Error("More Fragments flag was not set on first fragment")
	}
	if layer.FragOffset != 0 {
		if !p1Logged {
			t.Log(result[0].Dump())
			p1Logged = true
		}
		t.Errorf("first fragment's offset should be 0, but got %d", layer.FragOffset)
	}

	if !actions.VerifyIPv4Checksum(layer.Contents) {
		if !p1Logged {
			t.Log(result[0].Dump())
			p1Logged = true
		}
		t.Errorf("first fragment's checksum is invalid: %#04x", layer.Checksum)
	}

	// time to test fragment 2

	layer = result[1].NetworkLayer().(*layers.IPv4)
	if layer.Checksum == pktIPv4Layer.Checksum {
		if !p2Logged {
			t.Log(result[1].Dump())
			p2Logged = true
		}
		t.Errorf("checksum of second fragment is the same as the original packet (0x%x)", layer.Checksum)
	}
	if layer.Flags&layers.IPv4MoreFragments != 0 {
		if !p2Logged {
			t.Log(result[1].Dump())
			p2Logged = true
		}
		t.Error("More Fragments flag was set on second fragment")
	}

	fragOffset := (fragSize - (fragSize % 8)) / 8
	if layer.FragOffset != fragOffset {
		if !p2Logged {
			t.Log(result[1].Dump())
			p2Logged = true
		}
		t.Errorf("second fragment's offset should be %d, but got %d",
			fragOffset, layer.FragOffset)
	}

	frag2ExpectedLen := uint16(len(pktIPv4Layer.Payload)) - fragSize
	if layer.Length != frag2ExpectedLen {
		if !p2Logged {
			t.Log(result[1].Dump())
			p2Logged = true
		}
		t.Errorf("second fragment's offset should be %d, but got %d (total len %d)",
			frag2ExpectedLen, layer.FragOffset, len(ssh))
	}

	if !actions.VerifyIPv4Checksum(layer.Contents) {
		if !p2Logged {
			t.Log(result[1].Dump())
			p2Logged = true
		}
		t.Errorf("second fragment's checksum is invalid: %#04x", layer.Checksum)
	}
}

func TestActionTreeSimple(t *testing.T) {
	str := "[TCP:flags:S]-duplicate(send,send)-|"
	l := lexer.NewLexer(str)
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
	l := lexer.NewLexer(str)
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
			l := lexer.NewLexer(tc.elided)
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
