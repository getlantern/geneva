// Package common provides common functions for Geneva.
package common

import (
	"encoding/binary"

	"github.com/gopacket/gopacket/layers"
)

// UpdateTCPChecksum updates the TCP checksum field and the raw bytes for a gopacket TCP layer.
//
// The TCP checksum covers a pseudo-header derived from the IPv4 source and
// destination addresses, so ip must be the TCP layer's network layer. A freshly
// decoded packet does not carry that association, which is why the caller passes
// it explicitly; without it ComputeChecksum fails and the checksum would be left
// zero. ip may be nil only when the TCP layer already has its network layer set.
func UpdateTCPChecksum(tcp *layers.TCP, ip *layers.IPv4) {
	if ip != nil {
		// Ignoring the error is safe: it only reports an unsupported network
		// layer type, and *layers.IPv4 is always supported.
		_ = tcp.SetNetworkLayerForChecksum(ip)
	}

	// the ComputeChecksum method requires the checksum bytes in the raw packet to be zeroed out.
	tcp.Contents[16] = 0
	tcp.Contents[17] = 0

	chksum, _ := tcp.ComputeChecksum()

	tcp.Checksum = chksum
	binary.BigEndian.PutUint16(tcp.Contents[16:18], chksum)
}

// UpdateIPv4Checksum updates the IPv4 checksum field and the raw bytes for a gopacket IPv4 layer.
func UpdateIPv4Checksum(ip *layers.IPv4) {
	chksum := CalculateIPv4Checksum(ip.Contents)
	ip.Checksum = chksum
	binary.BigEndian.PutUint16(ip.Contents[10:12], chksum)
}

// CalculateIPv4Checksum calculates the IPv4 checksum for the given bytes.
// copied from gopacket/layers/ip4.go because they didn't export one. for whatever some reason..
func CalculateIPv4Checksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}

	for csum > 0xFFFF {
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}
