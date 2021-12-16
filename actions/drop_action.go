package actions

import "github.com/google/gopacket"

type DropAction struct{}

func (a *DropAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	return []gopacket.Packet{}
}

func (a *DropAction) String() string {
	return "drop"
}

var DefaultDropAction Action = &DropAction{}
