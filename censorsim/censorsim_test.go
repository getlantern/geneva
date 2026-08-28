package censorsim

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/getlantern/geneva/strategy"
)

const (
	clientIP = "10.0.0.1"
	serverIP = "93.184.216.34"
	censorIP = "203.0.113.1"
	sport    = uint16(49152)
	dport    = uint16(443)
	synSeq   = uint32(1000)
	// dataSeq is the client's first data sequence number, one past the SYN.
	dataSeq   = synSeq + 1
	serverSeq = uint32(5000)
)

// allTCPCensors is every censor that inspects content (i.e. excludes the dummy).
var allTCPCensors = []string{"1", "2", "3", "4", "5", "6", "7", "8", "8b", "9", "10", "11"}

func testConfig() Config {
	return Config{Forbidden: DefaultForbidden(), CensorIP: net.ParseIP(censorIP).To4()}
}

// forbiddenPayload returns a synthetic payload with the forbidden keyword embedded after an
// 8-byte prefix, plus that offset. A fragment split inside the keyword hides it from a censor's
// substring search.
func forbiddenPayload() (payload []byte, wordOffset int) {
	prefix := []byte("PREFIX!!")  // 8 bytes
	word := DefaultForbidden()[0] // "ultrasurf"
	suffix := []byte("--SUFFIX")  // 8 bytes

	payload = make([]byte, 0, len(prefix)+len(word)+len(suffix))
	payload = append(payload, prefix...)
	payload = append(payload, word...)
	payload = append(payload, suffix...)

	return payload, len(prefix)
}

func setFlags(tcp *layers.TCP, flags string) {
	for _, c := range flags {
		switch c {
		case 'S':
			tcp.SYN = true
		case 'A':
			tcp.ACK = true
		case 'P':
			tcp.PSH = true
		case 'R':
			tcp.RST = true
		case 'F':
			tcp.FIN = true
		}
	}
}

func mkTCP(t *testing.T, src, dst string, sp, dp uint16, seq, ack uint32, flags string, payload []byte) gopacket.Packet {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       1,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(src).To4(),
		DstIP:    net.ParseIP(dst).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sp),
		DstPort: layers.TCPPort(dp),
		Seq:     seq,
		Ack:     ack,
		Window:  65535,
	}
	setFlags(tcp, flags)
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	toSerialize := []gopacket.SerializableLayer{ip, tcp}
	if len(payload) > 0 {
		toSerialize = append(toSerialize, gopacket.Payload(payload))
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, toSerialize...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

type directedPacket struct {
	pkt gopacket.Packet
	dir strategy.Direction
}

// stream returns a full connection: handshake (SYN, SYN-ACK, ACK) followed by the client's data
// packet carrying payload. Outbound packets flow client->server; the SYN-ACK is inbound.
func stream(t *testing.T, payload []byte) []directedPacket {
	t.Helper()

	return []directedPacket{
		{mkTCP(t, clientIP, serverIP, sport, dport, synSeq, 0, "S", nil), strategy.DirectionOutbound},
		{mkTCP(t, serverIP, clientIP, dport, sport, serverSeq, dataSeq, "SA", nil), strategy.DirectionInbound},
		{mkTCP(t, clientIP, serverIP, sport, dport, dataSeq, serverSeq+1, "A", nil), strategy.DirectionOutbound},
		{mkTCP(t, clientIP, serverIP, sport, dport, dataSeq, serverSeq+1, "PA", payload), strategy.DirectionOutbound},
	}
}

// runStrategy applies dna to each packet in the connection (per direction) and feeds every
// resulting packet, in order, through the censor.
func runStrategy(t *testing.T, dna string, c Censor, payload []byte) {
	t.Helper()

	s, err := strategy.ParseStrategy(dna)
	if err != nil {
		t.Fatalf("ParseStrategy(%q): %v", dna, err)
	}

	for _, item := range stream(t, payload) {
		out, err := s.Apply(item.pkt, item.dir)
		if err != nil {
			t.Fatalf("Apply (%s): %v", item.dir, err)
		}
		for _, p := range out {
			c.Process(p)
		}
	}
}

// TestDummyNeverTriggers is the harness sanity check: the dummy censor ignores forbidden content.
func TestDummyNeverTriggers(t *testing.T) {
	t.Parallel()

	c, err := New("dummy", testConfig())
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := forbiddenPayload()
	runStrategy(t, `\/`, c, payload)
	if c.Triggered() {
		t.Fatal("dummy censor should never trigger")
	}
}

// TestNaiveStrategyIsCaught proves each censor bites: with a no-op strategy, the forbidden
// keyword reaches every censor intact and every one of them triggers.
func TestNaiveStrategyIsCaught(t *testing.T) {
	t.Parallel()

	for _, name := range allTCPCensors {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, err := New(name, testConfig())
			if err != nil {
				t.Fatal(err)
			}

			payload, _ := forbiddenPayload()
			runStrategy(t, `\/`, c, payload)
			if !c.Triggered() {
				t.Errorf("censor %s failed to catch the no-op strategy", name)
			}
		})
	}
}

// TestFragmentationSplitEvades confirms that a strategy which fragments the payload inside the
// forbidden keyword hides it from every censor's substring search (none of them reassemble).
func TestFragmentationSplitEvades(t *testing.T) {
	t.Parallel()

	payload, off := forbiddenPayload()
	// Split four bytes into the keyword so neither fragment contains it whole.
	dna := fmt.Sprintf("[TCP:flags:PA]-fragment{tcp:%d:true}-| \\/", off+4)

	for _, name := range allTCPCensors {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, err := New(name, testConfig())
			if err != nil {
				t.Fatal(err)
			}

			runStrategy(t, dna, c, payload)
			if c.Triggered() {
				t.Errorf("censor %s caught a keyword-splitting fragmentation strategy", name)
			}
		})
	}
}

// TestRSTTeardownEvadesTeardownCensors confirms that injecting an in-window RST before the data
// packet tears down the TCB of the teardown-style censors (6, 7, 8), so the following data is
// ignored. The RST copy is produced by duplicating the data packet and tampering its flags to R.
func TestRSTTeardownEvadesTeardownCensors(t *testing.T) {
	t.Parallel()

	dna := `[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:R},)-| \/`

	for _, name := range []string{"6", "7", "8"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, err := New(name, testConfig())
			if err != nil {
				t.Fatal(err)
			}

			payload, _ := forbiddenPayload()
			runStrategy(t, dna, c, payload)
			if c.Triggered() {
				t.Errorf("censor %s caught the RST-teardown strategy", name)
			}
		})
	}
}

// TestInjectedRSTsProduced checks that an RST-injecting censor emits the paired RSTs when it fires.
func TestInjectedRSTsProduced(t *testing.T) {
	t.Parallel()

	c, err := New("3", testConfig())
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := forbiddenPayload()
	var injected int
	s, _ := strategy.ParseStrategy(`\/`)
	for _, item := range stream(t, payload) {
		out, _ := s.Apply(item.pkt, item.dir)
		for _, p := range out {
			injected += len(c.Process(p).Injected)
		}
	}

	if !c.Triggered() {
		t.Fatal("censor 3 should have triggered")
	}
	// 5 client + 5 server RSTs.
	if injected != 10 {
		t.Errorf("censor 3 injected %d RSTs, want 10", injected)
	}
}

// TestChecksumValidationDistinguishes shows the ladder: a bad-checksum RST insertion tears down
// the checksum-blind Censor8 but not the checksum-validating Censor10, which ignores the bad
// packet and still catches the keyword.
func TestChecksumValidationDistinguishes(t *testing.T) {
	t.Parallel()

	// Duplicate the data packet, turn one copy into a RST whose checksum is deliberately wrong.
	dna := `[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:4444}),)-| \/`

	payload, _ := forbiddenPayload()

	c8, _ := New("8", testConfig())
	runStrategy(t, dna, c8, payload)
	if c8.Triggered() {
		t.Error("censor 8 (checksum-blind) should be evaded by the bad-checksum RST teardown")
	}

	payload, _ = forbiddenPayload()
	c10, _ := New("10", testConfig())
	runStrategy(t, dna, c10, payload)
	if !c10.Triggered() {
		t.Error("censor 10 (checksum-validating) should ignore the bad-checksum RST and still catch the keyword")
	}
}

// TestForbiddenSplitAcrossFragments is a direct unit check of the substring model, independent of
// the engine: a keyword split across two payloads is not detected in either half.
func TestForbiddenSplitAcrossFragments(t *testing.T) {
	t.Parallel()

	word := DefaultForbidden()[0]
	first := word[:4]
	second := word[4:]
	if containsForbidden(first, DefaultForbidden()) || containsForbidden(second, DefaultForbidden()) {
		t.Fatal("split halves should not match the forbidden keyword")
	}
	if !containsForbidden(bytes.Join([][]byte{first, second}, nil), DefaultForbidden()) {
		t.Fatal("rejoined halves should match the forbidden keyword")
	}
}
