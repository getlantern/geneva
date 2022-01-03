package actions

import "github.com/google/gopacket"

// DropAction is a Geneva action that drops a packet.
type DropAction struct{}

// Apply drops the given packet.
func (a *DropAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	return []gopacket.Packet{}, nil
}

// String returns a string representing the "drop" action.
func (a *DropAction) String() string {
	return "drop"
}

// DefaultDropAction is the default drop action.
// (DropAction is so simple that there is no need to allocate more than one.)
var DefaultDropAction *DropAction = &DropAction{}
