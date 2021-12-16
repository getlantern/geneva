package actions

import "github.com/google/gopacket"

type TamperMode int

const (
	TamperReplace = iota
	TamperCorrupt
)

type TamperAction struct {
	Proto       string
	Field       string
	Mode        TamperMode
	LeftAction  Action
	RightAction Action
}

func (a *TamperAction) Apply(packet gopacket.Packet) []gopacket.Packet {
	panic("unimplemented")
}
