// Package common provides common functions for Geneva.
package common

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

// UpdateTCPChecksum updates the TCP checksum field and the raw bytes for a gopacket TCP layer.
func UpdateTCPChecksum(tcp *layers.TCP) {
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
	buf := make([]byte, len(bytes), 60)
	copy(buf, bytes)

	// Clear checksum bytes
	buf[10] = 0
	buf[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(buf); i += 2 {
		csum += uint32(buf[i]) << 8
		csum += uint32(buf[i+1])
	}

	for csum > 0xFFFF {
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}
