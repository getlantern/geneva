package actions

import (
	"github.com/google/gopacket"
)

type SendAction struct{}

func (a *SendAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	return []gopacket.Packet{packet}
}

func (a *SendAction) String() string {
	return "send"
}

var DefaultSendAction *SendAction = &SendAction{}
