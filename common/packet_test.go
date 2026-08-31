package common

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// onesComplementSum returns the 16-bit ones-complement sum of b. A buffer whose
// checksum field is included sums to 0xffff when the checksum is valid.
func onesComplementSum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// TestUpdateTCPChecksumOnDecodedPacket guards the pseudo-header regression: a
// freshly decoded TCP layer carries no network-layer association, so
// UpdateTCPChecksum must be given the IPv4 layer or it would leave the checksum
// zeroed. This reproduces what a tamper/fragment action does at runtime.
func TestUpdateTCPChecksumOnDecodedPacket(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2},
	}
	tcp := &layers.TCP{SrcPort: 8080, DstPort: 44000, Seq: 1, SYN: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
		ip, tcp, gopacket.Payload([]byte("payload"))); err != nil {
		t.Fatal(err)
	}

	// Decode, mutate a field, then recompute — the runtime path.
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	dip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	dtcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	dtcp.ACK = true // change flags, invalidating the checksum
	dtcp.Contents[13] |= 0x10

	UpdateTCPChecksum(dtcp, dip)

	if dtcp.Checksum == 0 {
		t.Fatal("checksum left zero: network layer was not applied")
	}
	// Verify on the wire: pseudo-header + segment must sum to 0xffff.
	seg := append([]byte(nil), dtcp.Contents...)
	seg = append(seg, dtcp.Payload...)
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], dip.SrcIP.To4())
	copy(pseudo[4:8], dip.DstIP.To4())
	pseudo[9] = byte(layers.IPProtocolTCP)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	if got := onesComplementSum(pseudo); got != 0xffff {
		t.Fatalf("TCP checksum invalid on the wire: sum=%#04x, want 0xffff", got)
	}
}
