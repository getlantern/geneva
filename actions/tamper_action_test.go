package actions

import (
	"math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/geneva/internal/scanner"
)

func TestParseTamperAction(t *testing.T) {
	t.Parallel()

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
		}, {
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
		}, {
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

func TestParseTamperActionRejectsMalformedModes(t *testing.T) {
	t.Parallel()

	for _, rule := range []string{
		"tamper{TCP:seq:replace}",
		"tamper{TCP:seq:corrupt:1}",
		"tamper{TCP:seq}",
	} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			_, err := ParseTamperAction(scanner.NewScanner(rule))
			require.Error(t, err)
		})
	}
}

func TestTamperApplySerializesChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rule   string
		verify func(*testing.T, gopacket.Packet)
	}{
		{
			name: "TCP sequence",
			rule: "tamper{TCP:seq:replace:42}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				tcp, ok := packet.TransportLayer().(*layers.TCP)
				require.True(t, ok)
				assert.Equal(t, uint32(42), tcp.Seq)
			},
		},
		{
			name: "TCP payload",
			rule: "tamper{TCP:load:replace:changed}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				tcp, ok := packet.TransportLayer().(*layers.TCP)
				require.True(t, ok)
				assert.Equal(t, []byte("changed"), tcp.Payload)
				ip := packet.NetworkLayer().(*layers.IPv4) //nolint:forcetypeassert
				assert.Equal(t, int(ip.Length), len(ip.Contents)+len(ip.Payload))
			},
		},
		{
			name: "IPv4 TTL",
			rule: "tamper{IP:ttl:replace:9}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				ip, ok := packet.NetworkLayer().(*layers.IPv4)
				require.True(t, ok)
				assert.Equal(t, uint8(9), ip.TTL)
			},
		},
		{
			name: "IPv4 checksum",
			rule: "tamper{IP:checksum:replace:1}",
			verify: func(t *testing.T, packet gopacket.Packet) {
				ip, ok := packet.NetworkLayer().(*layers.IPv4)
				require.True(t, ok)
				assert.Equal(t, uint16(1), ip.Checksum)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			action, err := ParseTamperAction(scanner.NewScanner(test.rule))
			require.NoError(t, err)
			result, err := action.Apply(testPkt())
			require.NoError(t, err)
			require.Len(t, result, 1)
			test.verify(t, result[0])
		})
	}
}

func TestCorruptTamperConcurrentApply(t *testing.T) {
	t.Parallel()

	action, err := ParseTamperAction(scanner.NewScanner("tamper{TCP:seq:corrupt}"))
	require.NoError(t, err)

	const workers = 64
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, applyErr := action.Apply(testPkt())
			errs <- applyErr
		}()
	}
	wg.Wait()
	close(errs)
	for applyErr := range errs {
		require.NoError(t, applyErr)
	}
}

func TestTamperTCP(t *testing.T) {
	t.Parallel()

	type args struct {
		tcp      *layers.TCP
		field    TCPField
		valueGen tamperValueGen
	}

	//nolint:forcetypeassert
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "tcp tamper replace existing option",
			args: args{
				tcp:      testPkt().Layer(layers.LayerTypeTCP).(*layers.TCP),
				field:    TCPOptionMss,
				valueGen: &tamperReplaceGen{vBytes: []byte{0x0f, 0xff}},
			},
			want: []byte{
				0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x00,
				0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x0f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
				0x73, 0x74,
			},
		}, {
			name: "tcp tamper replace missing option",
			args: args{
				tcp:      testPkt().Layer(layers.LayerTypeTCP).(*layers.TCP),
				field:    TCPOptionAltCkhsum,
				valueGen: &tamperReplaceGen{vBytes: []byte{0xff, 0xff, 0xff}},
			},
			want: []byte{
				0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x00,
				0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x0e, 0x05, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0x54, 0x65, 0x73, 0x74,
			},
		}, {
			name: "tcp tamper replace payload",
			args: args{
				tcp:   testPkt().Layer(layers.LayerTypeTCP).(*layers.TCP),
				field: TCPLoad,
				valueGen: &tamperReplaceGen{
					vBytes: []byte{
						0x6d, 0x69, 0x73, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x46, 0x61, 0x77, 0x6b, 0x73,
					},
				},
			},
			want: []byte{
				0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x00,
				0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x69,
				0x73, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x46, 0x61, 0x77, 0x6b, 0x73,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, tamperTCP(tt.args.tcp, tt.args.field, tt.args.valueGen))

			got := append([]byte{}, tt.args.tcp.Contents...)
			got = append(got, tt.args.tcp.Payload...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func testPkt() gopacket.Packet {
	tcpBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x80, 0x06, 0xb9, 0x70, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
		0x00, 0x02, 0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
		0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
		0x73, 0x74,
	}

	return gopacket.NewPacket(tcpBytes, layers.LinkTypeEthernet, gopacket.Default)
}

// constSource is a rand.Source that always returns a fixed Int63, letting tests drive
// tamperCorruptGen deterministically.
type constSource int64

func (s constSource) Int63() int64 { return int64(s) }
func (s constSource) Seed(int64)   {}

// TestTamperCorruptGenFullRange is a regression test: the corrupt generator previously used
// Intn(1<<bitSize-1), which both overflowed on 32-bit builds for bitSize 32 and could never
// emit the field's maximum value. It must now produce every value in [0, 2^bitSize-1],
// including both endpoints, on any platform.
func TestTamperCorruptGenFullRange(t *testing.T) {
	t.Parallel()

	// math/rand's Uint32() returns uint32(Int63() >> 31); this constant makes Uint32()
	// deterministically return 0xffffffff.
	allOnes := constSource(int64(0xffffffff) << 31)
	if got := (&tamperCorruptGen{r: rand.New(allOnes)}).uint(32); got != 0xffffffff {
		t.Errorf("bitSize 32 with maxed source = %#x, expected 0xffffffff", got)
	}

	maxed := &tamperCorruptGen{r: rand.New(constSource(int64(0xffffffff) << 31))}
	for bitSize, want := range map[int]uint32{8: 0xff, 16: 0xffff} {
		if got := maxed.uint(bitSize); got != want {
			t.Errorf("bitSize %d with maxed source = %#x, expected %#x", bitSize, got, want)
		}
	}

	zero := &tamperCorruptGen{r: rand.New(constSource(123))}
	for _, bitSize := range []int{8, 16, 32} {
		if got := zero.uint(bitSize); got != 0 {
			t.Errorf("bitSize %d with zero source = %#x, expected 0", bitSize, got)
		}
	}
}

// TestTCPDerivedFieldPolicy locks the tamper dependent-field policy: every known TCP field must
// be classified exactly once, so that adding a new enum member forces an explicit decision
// instead of silently emitting stale lengths.
func TestTCPDerivedFieldPolicy(t *testing.T) {
	t.Parallel()

	options := []TCPField{
		TCPOptionEol, TCPOptionNop, TCPOptionMss, TCPOptionWscale,
		TCPOptionSackok, TCPOptionSack, TCPOptionTimestamp,
		TCPOptionAltCkhsum, TCPOptionMd5Header, TCPOptionUto,
	}
	for _, f := range options {
		if !tcpFieldIsOption(f) {
			t.Errorf("field %d should be classified as a TCP option", f)
		}
		if !tcpAffectsIPLength(f) {
			t.Errorf("option %d changes the TCP header size and thus the IP length", f)
		}
	}

	plainFields := []TCPField{
		TCPFieldSrcPort, TCPFieldDstPort, TCPFieldSeq, TCPFieldAck, TCPFieldDataOff,
		TCPFieldFlags, TCPFieldWindow, TCPFieldUrgent, TCPFieldChecksum, TCPLoad,
	}
	for _, f := range plainFields {
		if tcpFieldIsOption(f) {
			t.Errorf("field %d should not be classified as a TCP option", f)
		}
		wantLengthImpact := f == TCPLoad
		if tcpAffectsIPLength(f) != wantLengthImpact {
			t.Errorf("field %d tcpAffectsIPLength = %t, expected %t", f, tcpAffectsIPLength(f), wantLengthImpact)
		}
	}
}
