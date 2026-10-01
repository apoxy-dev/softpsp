// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/replay"
)

var (
	testMaster = bytes.Repeat([]byte{7}, psp.MasterKeyLen)
	src4       = netip.MustParseAddr("10.1.0.5")
	src6       = netip.MustParseAddr("fd00:1::5")
)

func testSA() RxSA {
	return RxSA{
		Master:  testMaster,
		Version: psp.AESGCM128,
		VNI:     0x123,
		Sources: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24"), netip.MustParsePrefix("fd00:1::/64")},
		MTU:     1280,
	}
}

func newTable(tb testing.TB, rowBits int) *RxTable {
	tb.Helper()
	t, err := NewRxTable(RxConfig{RowBits: rowBits})
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

// sender seals packets as the peer that has the SA key.
type sender struct {
	aead cipher.AEAD
	h    psp.Header
}

func newSender(tb testing.TB, spi uint32, key []byte, sa RxSA) *sender {
	tb.Helper()
	aead, err := psp.NewAEAD(key)
	if err != nil {
		tb.Fatal(err)
	}
	return &sender{aead: aead, h: psp.Header{Version: sa.Version, SPI: spi, VNI: sa.VNI, Flags: psp.FlagSeq}}
}

// add adds sa to t and returns its SPI and a sender for it.
func add(tb testing.TB, t *RxTable, sa RxSA) (uint32, *sender) {
	tb.Helper()
	spi, key, err := t.Add(sa)
	if err != nil {
		tb.Fatal(err)
	}
	return spi, newSender(tb, spi, key, sa)
}

// seal returns a packet with the sequence number seq. edit can change the
// header before the seal.
func (s *sender) seal(tb testing.TB, seq uint32, inner []byte, edit func(*psp.Header)) []byte {
	tb.Helper()
	h := s.h
	h.Seq, h.IV = seq, uint64(seq)
	if edit != nil {
		edit(&h)
	}
	pkt := make([]byte, len(inner)+psp.Overhead)
	if _, err := psp.Seal(s.aead, h, pkt, inner); err != nil {
		tb.Fatal(err)
	}
	return pkt
}

// ipPacket returns an n-byte IP packet from src.
func ipPacket(src netip.Addr, n int) []byte {
	if src.Is4() {
		p := make([]byte, max(n, 20))
		p[0] = 0x45
		copy(p[12:16], src.AsSlice())
		return p
	}
	p := make([]byte, max(n, 40))
	p[0] = 0x60
	copy(p[8:24], src.AsSlice())
	return p
}

func TestReceive(t *testing.T) {
	type step struct {
		seq   uint32
		inner []byte // Default: a 60-byte packet from src4.
		edit  func(*psp.Header)
		want  error
	}
	from := func(addr string) []byte { return ipPacket(netip.MustParseAddr(addr), 60) }
	noSeq := func(h *psp.Header) { h.Flags = 0 }
	otherVNI := func(h *psp.Header) { h.VNI++ }
	limit9000 := psp.PacketLimit(9000)
	const w = replay.WindowSize

	cases := []struct {
		name  string
		mtu   int
		steps []step
	}{
		{name: "in order", steps: []step{{seq: 0}, {seq: 1}, {seq: 2}, {seq: 3}}},
		{name: "duplicates", steps: []step{
			{seq: 5}, {seq: 5, want: ErrReplay}, {seq: 6}, {seq: 5, want: ErrReplay}, {seq: 6, want: ErrReplay},
		}},
		{name: "reorder", steps: []step{
			{seq: 10}, {seq: 3}, {seq: 7}, {seq: 9}, {seq: 3, want: ErrReplay}, {seq: 4},
		}},
		{name: "window edge", steps: []step{
			{seq: w + 10}, {seq: 9, want: ErrReplay}, {seq: 10}, {seq: 10, want: ErrReplay},
		}},
		{name: "jump ahead", steps: []step{
			{seq: 0}, {seq: 1 << 20}, {seq: 0, want: ErrReplay}, {seq: 1<<20 - 1},
		}},
		{name: "limit at MTU 1280", steps: []step{
			{seq: 1<<31 - 1}, {seq: 1 << 31, want: ErrLimit}, {seq: math.MaxUint32, want: ErrLimit},
		}},
		{name: "limit at MTU 9000", mtu: 9000, steps: []step{
			{seq: limit9000 - 1}, {seq: limit9000, want: ErrLimit},
		}},
		{name: "flag S clear", steps: []step{{seq: 1, edit: noSeq, want: ErrNoSeq}, {seq: 1}}},
		{name: "other VNI", steps: []step{{seq: 1, edit: otherVNI, want: ErrVNI}, {seq: 1}}},
		{name: "IPv4 source", steps: []step{
			{seq: 1, inner: from("10.2.0.5"), want: ErrSource}, {seq: 1, inner: from("10.1.0.255")},
		}},
		{name: "IPv6 source", steps: []step{
			{seq: 1, inner: from("fd00:2::5"), want: ErrSource}, {seq: 1, inner: from("fd00:1::ffff")},
		}},
		{name: "IPv4-mapped IPv6 source", steps: []step{{seq: 1, inner: from("::ffff:10.1.0.5"), want: ErrSource}}},
		{name: "short inner", steps: []step{
			{seq: 1, inner: []byte{0x45, 0, 0, 0}, want: ErrSource},
			{seq: 2, inner: ipPacket(src6, 40)[:39], want: ErrSource},
			{seq: 3, inner: ipPacket(src4, 20)},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := testSA()
			if tc.mtu != 0 {
				sa.MTU = tc.mtu
			}
			tab := newTable(t, 4)
			_, s := add(t, tab, sa)
			for i, st := range tc.steps {
				inner := st.inner
				if inner == nil {
					inner = ipPacket(src4, 60)
				}
				got, vni, err := tab.Queue(0).Receive(s.seal(t, st.seq, inner, st.edit))
				if !errors.Is(err, st.want) {
					t.Fatalf("step %d (seq %d): got %v, want %v", i, st.seq, err, st.want)
				}
				if err == nil && (!bytes.Equal(got, inner) || vni != sa.VNI) {
					t.Fatalf("step %d: got inner %x VNI %#x, want %x VNI %#x", i, got, vni, inner, sa.VNI)
				}
			}
		})
	}
}

// TestReceiveNoSA checks packets that must not find a row.
func TestReceiveNoSA(t *testing.T) {
	inner := ipPacket(src4, 60)
	cases := []struct {
		name string
		pkt  func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte
		want error
	}{
		{"bad header", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			return make([]byte, 100)
		}, psp.ErrNextHdr},
		{"deleted", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			if !tab.Delete(spi) {
				t.Fatal("Delete found no SA")
			}
			return s.seal(t, 1, inner, nil)
		}, ErrUnknownSA},
		{"other random bits", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			other := spi ^ 1<<tab.rowBits
			key, _ := psp.DeriveSAKey(testMaster, other, psp.AESGCM128)
			return newSender(t, other, key, testSA()).seal(t, 1, inner, nil)
		}, ErrUnknownSA},
		{"other master index", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			return s.seal(t, 1, inner, func(h *psp.Header) { h.SPI ^= 1 << 31 })
		}, ErrUnknownSA},
		{"other version", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			return s.seal(t, 1, inner, func(h *psp.Header) { h.Version = psp.AESGCM256 })
		}, ErrUnknownSA},
		{"row used again", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			tab.Delete(spi)
			if spi2, _ := add(t, tab, testSA()); spi2&tab.rowMask != spi&tab.rowMask || spi2 == spi {
				t.Fatalf("got SPI %#x after %#x, want the same row and a new SPI", spi2, spi)
			}
			return s.seal(t, 1, inner, nil)
		}, ErrUnknownSA},
		{"expired", func(t *testing.T, tab *RxTable, spi uint32, s *sender) []byte {
			if n := tab.Expire(time.Now()); n != 0 {
				t.Fatalf("Expire now removed %d SAs", n)
			}
			if n := tab.Expire(time.Now().Add(DefaultLifetime)); n != 1 {
				t.Fatalf("Expire after the lifetime removed %d SAs, want 1", n)
			}
			return s.seal(t, 1, inner, nil)
		}, ErrUnknownSA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 1) // One row, so a new SA uses the same row.
			spi, s := add(t, tab, testSA())
			if _, _, err := tab.Queue(0).Receive(tc.pkt(t, tab, spi, s)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if n := tab.Queue(0).Stats().NoMatch; n != 1 {
				t.Fatalf("NoMatch = %d, want 1", n)
			}
		})
	}
}

func TestStats(t *testing.T) {
	tab := newTable(t, 4)
	spi, s := add(t, tab, testSA())
	inner := ipPacket(src4, 60)
	tampered := s.seal(t, 9, inner, nil)
	tampered[len(tampered)-1] ^= 1
	_, other := add(t, tab, testSA())
	wrongKey := other.seal(t, 9, inner, func(h *psp.Header) { h.SPI = spi })

	for _, pkt := range [][]byte{
		s.seal(t, 1, inner, nil),
		s.seal(t, 2, inner, nil),
		s.seal(t, 2, inner, nil), // Replay.
		s.seal(t, 3, ipPacket(netip.MustParseAddr("fd00:2::5"), 60), nil), // Source.
		s.seal(t, 4, inner, func(h *psp.Header) { h.Flags = 0 }),
		tampered,
		wrongKey,
		s.seal(t, 9, inner, nil), // The ICV failures did not use seq 9.
	} {
		tab.Queue(0).Receive(pkt)
	}
	got, ok := tab.Stats(spi)
	want := RxStats{Packets: 3, ICVFailures: 2, Replays: 1, Rejects: 2, Seq: 9}
	if !ok || got != want {
		t.Fatalf("Stats = %+v, %v, want %+v", got, ok, want)
	}
	if _, ok := tab.Stats(spi ^ 1<<tab.rowBits); ok {
		t.Fatal("Stats found an SA for an SPI with other random bits")
	}
}

func TestAdd(t *testing.T) {
	tab := newTable(t, 8)
	seen := map[uint32]bool{}
	for i := range 20 {
		sa := testSA()
		sa.MasterIndex = i % 2
		sa.Version = psp.Version(i % 3 % 2)
		spi, key, err := tab.Add(sa)
		if err != nil {
			t.Fatal(err)
		}
		row := spi & 0xff
		if psp.MasterKeyIndex(spi) != sa.MasterIndex || row == 0 || seen[row] {
			t.Fatalf("SPI %#x: want master key %d and a new row other than 0", spi, sa.MasterIndex)
		}
		seen[row] = true
		want, _ := psp.DeriveSAKey(testMaster, spi, sa.Version)
		if !bytes.Equal(key, want) {
			t.Fatalf("SPI %#x: key %x, want KDF(master, SPI) %x", spi, key, want)
		}
	}

	cases := []struct {
		name string
		edit func(*RxSA)
	}{
		{"short master", func(sa *RxSA) { sa.Master = sa.Master[:16] }},
		{"master index 2", func(sa *RxSA) { sa.MasterIndex = 2 }},
		{"master index -1", func(sa *RxSA) { sa.MasterIndex = -1 }},
		{"version 2", func(sa *RxSA) { sa.Version = 2 }},
		{"VNI too big", func(sa *RxSA) { sa.VNI = psp.MaxVNI + 1 }},
		{"MTU 0", func(sa *RxSA) { sa.MTU = 0 }},
		{"invalid prefix", func(sa *RxSA) { sa.Sources = []netip.Prefix{{}} }},
		{"lane of no queue", func(sa *RxSA) { sa.Lane = 1 }},
		{"lane -2", func(sa *RxSA) { sa.Lane = -2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := testSA()
			tc.edit(&sa)
			if _, _, err := tab.Add(sa); err == nil {
				t.Fatal("Add accepted the SA")
			}
		})
	}
}

func TestFullAndDelete(t *testing.T) {
	tab := newTable(t, 2) // Rows 1 to 3.
	var spis []uint32
	for range 3 {
		spi, _ := add(t, tab, testSA())
		spis = append(spis, spi)
	}
	if _, _, err := tab.Add(testSA()); !errors.Is(err, ErrFull) {
		t.Fatalf("Add to a full table: got %v, want %v", err, ErrFull)
	}
	if tab.Delete(spis[1] ^ 1<<tab.rowBits) {
		t.Fatal("Delete removed an SA for an SPI with other random bits")
	}
	if !tab.Delete(spis[1]) || tab.Delete(spis[1]) {
		t.Fatal("Delete must remove the SA once")
	}
	if spi, _, err := tab.Add(testSA()); err != nil || spi&tab.rowMask != spis[1]&tab.rowMask {
		t.Fatalf("Add after Delete: SPI %#x, %v, want row %d", spi, err, spis[1]&tab.rowMask)
	}
}

// TestNoSPIReuse checks that a row never gives the same SPI twice, and that a
// row with no new SPIs left is not used again.
func TestNoSPIReuse(t *testing.T) {
	tab := newTable(t, 1)
	seen := map[uint32]bool{}
	for range 2000 {
		spi, _ := add(t, tab, testSA())
		if seen[spi] {
			t.Fatalf("SPI %#x given twice", spi)
		}
		seen[spi] = true
		tab.Delete(spi)
	}

	tab.left[1] = 1
	spi, _ := add(t, tab, testSA())
	tab.Delete(spi)
	if _, _, err := tab.Add(testSA()); !errors.Is(err, ErrFull) {
		t.Fatalf("Add with the row used up: got %v, want %v", err, ErrFull)
	}
}

func TestNewRxTable(t *testing.T) {
	cases := []struct {
		cfg     RxConfig
		wantErr bool
	}{
		{RxConfig{}, false},
		{RxConfig{RowBits: 1, Lifetime: time.Second}, false},
		{RxConfig{RowBits: 25}, true},
		{RxConfig{RowBits: -1}, true},
		{RxConfig{Lifetime: -time.Second}, true},
		{RxConfig{Queues: MaxQueues}, false},
		{RxConfig{Queues: MaxQueues + 1}, true},
		{RxConfig{Queues: -1}, true},
	}
	for _, tc := range cases {
		tab, err := NewRxTable(tc.cfg)
		if (err != nil) != tc.wantErr {
			t.Fatalf("NewRxTable(%+v): error %v, want error %v", tc.cfg, err, tc.wantErr)
		}
		if err == nil && tc.cfg == (RxConfig{}) && (len(tab.rows) != 1<<DefaultRowBits || tab.lifetime != DefaultLifetime || tab.Queues() != 1) {
			t.Fatalf("defaults: %d rows, lifetime %v, %d queues", len(tab.rows), tab.lifetime, tab.Queues())
		}
	}
}

func TestReceiveNoAllocs(t *testing.T) {
	tab := newTable(t, 4)
	_, s := add(t, tab, testSA())
	pkts := make([][]byte, 200)
	for i := range pkts {
		pkts[i] = s.seal(t, uint32(i), ipPacket(src4, 1280), nil)
	}
	i := 0
	if a := testing.AllocsPerRun(100, func() {
		if _, _, err := tab.Queue(0).Receive(pkts[i]); err != nil {
			t.Fatal(err)
		}
		i++
	}); a != 0 {
		t.Fatalf("Receive: %v allocs per run, want 0", a)
	}
}

// FuzzReceive seals any inner bytes and header fields with a real SA key, so
// the checks after decryption see them.
func FuzzReceive(f *testing.F) {
	f.Add(ipPacket(src4, 60), uint32(1), psp.FlagSeq, uint8(0))
	f.Add(ipPacket(src6, 40), uint32(1<<31), uint8(0xff), uint8(1))
	f.Add([]byte{0x45}, uint32(0), psp.FlagSeq, uint8(0))
	tab := newTable(f, 4)
	sa := testSA()
	spi, s := add(f, tab, sa)
	row := tab.rows[spi&tab.rowMask].Load()
	f.Fuzz(func(t *testing.T, inner []byte, seq uint32, flags uint8, vniXor uint8) {
		if len(inner) == 0 || (inner[0]>>4 != 4 && inner[0]>>4 != 6) {
			return
		}
		row.window = replay.Window{} // Each input starts with an empty window.
		got, vni, err := tab.Queue(0).Receive(s.seal(t, seq, inner, func(h *psp.Header) {
			h.Flags = flags
			h.VNI ^= uint32(vniXor)
		}))
		if err != nil {
			return
		}
		src, ok := innerSource(got)
		if !bytes.Equal(got, inner) || vni != sa.VNI || flags&psp.FlagSeq == 0 || seq >= psp.PacketLimit(sa.MTU) ||
			!ok || !(sa.Sources[0].Contains(src) || sa.Sources[1].Contains(src)) {
			t.Fatalf("Receive accepted seq %d flags %#x VNI %#x inner %x", seq, flags, vni, inner)
		}
		if st, _ := tab.Stats(spi); st.Packets == 0 {
			t.Fatal("no packet counted")
		}
	})
}

func BenchmarkReceive(b *testing.B) {
	for _, n := range []int{64, 1280} {
		// Receive decrypts in place, so each loop copies a sealed packet first.
		// The copy is in the time. The window is cleared each round of packets.
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			tab := newTable(b, 4)
			spi, s := add(b, tab, testSA())
			row := tab.rows[spi&tab.rowMask].Load()
			pkts := make([][]byte, 1024)
			for i := range pkts {
				pkts[i] = s.seal(b, uint32(i), ipPacket(src4, n), nil)
			}
			buf := make([]byte, len(pkts[0]))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				copy(buf, pkts[i])
				if _, _, err := tab.Queue(0).Receive(buf); err != nil {
					b.Fatal(err)
				}
				if i++; i == len(pkts) {
					i = 0
					row.window = replay.Window{}
				}
			}
		})
	}
	b.Run("unknown SPI", func(b *testing.B) {
		tab := newTable(b, 4)
		spi, s := add(b, tab, testSA())
		pkt := s.seal(b, 1, ipPacket(src4, 64), nil)
		tab.Delete(spi)
		b.ReportAllocs()
		for b.Loop() {
			if _, _, err := tab.Queue(0).Receive(pkt); err != ErrUnknownSA {
				b.Fatal(err)
			}
		}
	})
}
