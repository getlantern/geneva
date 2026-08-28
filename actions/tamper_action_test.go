package actions

import (
	"bytes"
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

// seededTamperCorruptGen returns a tamperCorruptGen whose state is fixed at seed, letting
// tests drive the generator deterministically.
func seededTamperCorruptGen(seed uint64) *tamperCorruptGen {
	g := &tamperCorruptGen{}
	g.state.Store(seed)
	return g
}

// TestTamperCorruptGenDeterministic locks in the SplitMix64-based generator: seeding the
// same state must reproduce the same sequence, so any accidental change to the algorithm
// (or to which state values are drawn) is caught.
func TestTamperCorruptGenDeterministic(t *testing.T) {
	t.Parallel()

	wantUint32 := []uint32{
		0x2feb6e95, 0xb266f103, 0x130f9f52, 0x0e4ae394, 0x244823f2, 0x3c80db06, 0x45376d5d,
		0x9e9e2fa4, 0x0b3d7dd5, 0x297f77ae,
	}
	g := seededTamperCorruptGen(42)
	for i, want := range wantUint32 {
		if got := g.uint(32); got != want {
			t.Fatalf("draw %d = %#x, expected %#x", i, got, want)
		}
	}

	wantBytes := []byte{0x95, 0x6e, 0xeb, 0x2f, 0x26, 0x32, 0xd7, 0xbd, 0x03}
	got := seededTamperCorruptGen(42).bytes(9)
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("bytes(9) = %x, expected %x", got, wantBytes)
	}
}

// TestTamperCorruptGenFullRange is a regression test: the corrupt generator previously used
// Intn(1<<bitSize-1), which both overflowed on 32-bit builds for bitSize 32 and could never
// emit the field's maximum value. It must now produce every value in [0, 2^bitSize-1].
func TestTamperCorruptGenFullRange(t *testing.T) {
	t.Parallel()

	const draws = 100000

	g := seededTamperCorruptGen(1)
	var ones, zeros [32]bool
	var min, max uint32 = 0xffffffff, 0
	for range draws {
		v := g.uint(32)
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		for b := range ones {
			if v&(1<<uint(b)) != 0 {
				ones[b] = true
			} else {
				zeros[b] = true
			}
		}
	}

	// Every bit is reachable as both 0 and 1, so the generator spans the full width of the
	// field (the old Intn-based implementation could never set bit 31 on 32-bit builds). With
	// 100k draws the exact endpoints 0 and 0xffffffff are not guaranteed, but the extremes
	// must get close to them.
	for b := range ones {
		if !ones[b] || !zeros[b] {
			t.Fatalf("bit %d not reachable as both 0 and 1 after %d draws", b, draws)
		}
	}
	if min >= 1<<16 {
		t.Errorf("minimum drawn value = %#x, generator not reaching low values", min)
	}
	if max <= 0xffffffff-(1<<16) {
		t.Errorf("maximum drawn value = %#x, generator not reaching high values", max)
	}
}

func TestTamperCorruptGenBytes(t *testing.T) {
	t.Parallel()

	g := seededTamperCorruptGen(7)

	// Lengths up to 20 are honored exactly.
	for _, n := range []int{0, 1, 8, 20} {
		if got := len(g.bytes(n)); got != n {
			t.Errorf("len(bytes(%d)) = %d", n, got)
		}
	}

	// Lengths over 20 get a random length in [0, n).
	var sawShort bool
	for range 100 {
		if got := len(g.bytes(64)); got < 64 {
			sawShort = true
			break
		}
	}
	if !sawShort {
		t.Error("bytes(64) never produced a shortened random length")
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
