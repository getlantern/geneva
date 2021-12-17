package actions

import "github.com/google/gopacket"

// TamperMode describes the way that the "tamper" action can manipulate a packet.
type TamperMode int

const (
	// TamperReplace replaces the value of a packet field with the given value.
	TamperReplace = iota
	// TamperCorrupt replaces the value of a packet field with a randomly-generated value.
	TamperCorrupt
	// TamperAdd adds the value to a packet field.
	TamperAdd
)

// TamperAction is a Geneva action that modifies packets (typically values in the packet header).
type TamperAction struct {
	// Proto is the protocol layer where the modification will occur.
	Proto string
	// Field is the layer field to modify.
	Field string
	// Mode indicates how the modification should happen.
	Mode TamperMode
	// Action is the action to apply to the packet after modification.
	Action Action
}

// Apply applies this action to the given packet.
func (a *TamperAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	panic("unimplemented")
}
