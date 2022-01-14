package actions

import "github.com/google/gopacket"

// SendAction is a Geneva action to send a packet.
type SendAction struct{}

// Apply returns the packet unchanged.
func (a *SendAction) Apply(packet gopacket.Packet) ([]gopacket.Packet, error) {
	return []gopacket.Packet{packet}, nil
}

// String returns a string representing the "send" action.
func (a *SendAction) String() string {
	return "send"
}

// DefaultSendAction is the default send action.
//
// (SendAction is so simple that there is no need to allocate more than one.)
var DefaultSendAction = &SendAction{}
