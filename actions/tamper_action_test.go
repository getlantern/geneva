package actions

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/getlantern/geneva/internal/scanner"
)

func TestParseTamperAction(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		want    Action
		wantErr bool
	}{
		{
			name: "TCP tamper action replace uint",
			rule: "tamper{TCP:dataofs:replace:10}",
			want: &TCPTamperAction{
				TamperAction: TamperAction{
					Proto:    "TCP",
					Field:    "dataofs",
					NewValue: "10",
					Mode:     TamperReplace,
					Action:   &SendAction{},
				},
				field:    TCPFieldDataOff,
				valueGen: &tamperReplaceGen{vUint: 10},
			},
			wantErr: false,
		},
		{
			name: "TCP tamper action replace bytes",
			rule: "tamper{TCP:options-mss:replace:15}",
			want: &TCPTamperAction{
				TamperAction: TamperAction{
					Proto:    "TCP",
					Field:    "options-mss",
					NewValue: "15",
					Mode:     TamperReplace,
					Action:   &SendAction{},
				},
				field:    TCPOptionMss,
				valueGen: &tamperReplaceGen{vBytes: []byte{0x00, 0x0f}},
			},
			wantErr: false,
		},
		{
			name: "IPv4 tamper action replace uint",
			rule: "tamper{IP:ttl:replace:15}",
			want: &IPv4TamperAction{
				TamperAction: TamperAction{
					Proto:    "IP",
					Field:    "ttl",
					NewValue: "15",
					Mode:     TamperReplace,
					Action:   &SendAction{},
				},
				field:    IPv4FieldTTL,
				valueGen: &tamperReplaceGen{vUint: 15},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := scanner.NewScanner(tt.rule)
			got, err := ParseTamperAction(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTamperAction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTamperAction() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestTamperTCPOptions(t *testing.T) {
	type args struct {
		tcp      *layers.TCP
		field    TCPField
		valueGen tamperValueGen
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "",
			args:    args{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tamperTCP(tt.args.tcp, tt.args.field, tt.args.valueGen); (err != nil) != tt.wantErr {
				t.Errorf("tamperTCP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func tcpTestPkt() *layers.TCP {
	tcpBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x80, 0x06, 0xb9, 0x70, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
		0x00, 0x02, 0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	pkt := gopacket.NewPacket(tcpBytes, layers.LinkTypeEthernet, gopacket.Default)
	return pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
}
