// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"testing"
)

// testAEAD returns the AEAD for a fixed SA key of the suite.
func testAEAD(tb testing.TB, v Version) cipher.AEAD {
	tb.Helper()
	key := make([]byte, v.KeyLen())
	for i := range key {
		key[i] = byte(i*7 + int(v))
	}
	aead, err := NewAEAD(key)
	if err != nil {
		tb.Fatal(err)
	}
	return aead
}

// testInner returns an n-byte packet that starts with the IP version nibble.
func testInner(ipv, n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i)
	}
	if n > 0 {
		p[0] = byte(ipv<<4 | 5)
	}
	return p
}

// sealBoth seals inner with Seal and with SealInPlace, checks that both give
// the same bytes, and returns them.
func sealBoth(tb testing.TB, aead cipher.AEAD, h Header, inner []byte) []byte {
	tb.Helper()
	cross := make([]byte, len(inner)+Overhead)
	n, err := Seal(aead, h, cross, inner)
	if err != nil {
		tb.Fatalf("Seal: %v", err)
	}
	if n != len(cross) {
		tb.Fatalf("Seal length: got %d, want %d", n, len(cross))
	}

	const headroom = PrefixLen + 42 // Room for outer headers too.
	buf := make([]byte, headroom+len(inner)+ICVLen+3)
	copy(buf[headroom:], inner)
	start, length, err := SealInPlace(aead, h, buf, headroom, len(inner))
	if err != nil {
		tb.Fatalf("SealInPlace: %v", err)
	}
	if start != headroom-PrefixLen || length != len(cross) {
		tb.Fatalf("SealInPlace window: got (%d, %d), want (%d, %d)", start, length, headroom-PrefixLen, len(cross))
	}
	if got := buf[start : start+length]; !bytes.Equal(got, cross) {
		tb.Fatalf("in-place and cross-buffer bytes differ\n in-place %x\n    cross %x", got, cross)
	}
	return cross
}

// openBoth opens pkt with Open and with OpenInPlace and checks both give inner.
func openBoth(tb testing.TB, aead cipher.AEAD, pkt, inner []byte) {
	tb.Helper()
	dst := make([]byte, len(pkt))
	n, err := Open(aead, dst, pkt)
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(dst[:n], inner) {
		tb.Fatalf("Open inner\n got %x\nwant %x", dst[:n], inner)
	}
	got, err := OpenInPlace(aead, bytes.Clone(pkt))
	if err != nil {
		tb.Fatalf("OpenInPlace: %v", err)
	}
	if !bytes.Equal(got, inner) {
		tb.Fatalf("OpenInPlace inner\n got %x\nwant %x", got, inner)
	}
}

func TestSealOpen(t *testing.T) {
	for _, v := range []Version{AESGCM128, AESGCM256} {
		for _, ipv := range []int{4, 6} {
			for _, n := range []int{1, 20, 40, 1280, 1400, 9000} {
				t.Run(fmt.Sprintf("v%d/IPv%d/%d", v, ipv, n), func(t *testing.T) {
					aead := testAEAD(t, v)
					h := Header{Version: v, SPI: 0x80000001, IV: uint64(n), VNI: 0xabcdef, Flags: FlagSeq, Seq: 42}
					inner := testInner(ipv, n)
					pkt := sealBoth(t, aead, h, inner)

					got, err := ParseHeader(pkt)
					if err != nil {
						t.Fatalf("ParseHeader: %v", err)
					}
					h.NextHdr = NextHdrV4
					if ipv == 6 {
						h.NextHdr = NextHdrV6
					}
					if got != h {
						t.Fatalf("header\n got %+v\nwant %+v", got, h)
					}
					openBoth(t, aead, pkt, inner)
				})
			}
		}
	}
}

func TestSealErrors(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	good := Header{SPI: 1}
	inner := testInner(4, 20)
	cases := []struct {
		name    string
		h       Header
		inner   []byte
		dst     int // len(dst) for Seal.
		off     int // off for SealInPlace.
		tail    int // Tailroom for SealInPlace.
		wantErr error
	}{
		{name: "version 2", h: Header{Version: 2, SPI: 1}, inner: inner, dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrVersion},
		{name: "SPI 0", h: Header{}, inner: inner, dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrSPI},
		{name: "SPI MSB only", h: Header{SPI: 0x80000000}, inner: inner, dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrSPI},
		{name: "VNI too big", h: Header{SPI: 1, VNI: MaxVNI + 1}, inner: inner, dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrVNI},
		{name: "empty inner", h: good, inner: nil, dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrNextHdr},
		{name: "not IP", h: good, inner: testInner(5, 20), dst: 60, off: PrefixLen, tail: ICVLen, wantErr: ErrNextHdr},
		{name: "small dst or tailroom", h: good, inner: inner, dst: 59, off: PrefixLen, tail: ICVLen - 1, wantErr: ErrBuffer},
		{name: "no headroom", h: good, inner: inner, dst: 59, off: PrefixLen - 1, tail: ICVLen, wantErr: ErrBuffer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Seal(aead, tc.h, make([]byte, tc.dst), tc.inner); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Seal: got %v, want %v", err, tc.wantErr)
			}
			buf := make([]byte, tc.off+len(tc.inner)+tc.tail)
			copy(buf[tc.off:], tc.inner)
			if _, _, err := SealInPlace(aead, tc.h, buf, tc.off, len(tc.inner)); !errors.Is(err, tc.wantErr) {
				t.Fatalf("SealInPlace: got %v, want %v", err, tc.wantErr)
			}
		})
	}
	if _, _, err := SealInPlace(aead, good, make([]byte, 100), PrefixLen, -1); !errors.Is(err, ErrBuffer) {
		t.Fatalf("SealInPlace with n < 0: got %v, want %v", err, ErrBuffer)
	}
}

func TestOpenErrors(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	inner := testInner(4, 64)
	pkt := sealBoth(t, aead, Header{SPI: 1, IV: 1, VNI: 3, Flags: FlagSeq, Seq: 1}, inner)

	// An inner IPv4 packet under Next Header 41. It authenticates, and Open
	// must still drop it.
	mismatch := make([]byte, len(pkt))
	(&Header{NextHdr: NextHdrV6, SPI: 1, IV: 2}).put(mismatch)
	aead.Seal(mismatch[PrefixLen:PrefixLen], mismatch[nonceOff:HeaderLen], inner, mismatch[:PrefixLen])

	flip := func(i int) []byte {
		p := bytes.Clone(pkt)
		p[i] ^= 0x01
		return p
	}
	cases := []struct {
		name    string
		aead    cipher.AEAD
		pkt     []byte
		dst     int
		wantErr error
	}{
		{name: "next header", aead: aead, pkt: flip(0), dst: len(pkt), wantErr: ErrAuth},
		{name: "R bit", aead: aead, pkt: flip(2), dst: len(pkt), wantErr: ErrAuth},
		{name: "SPI", aead: aead, pkt: flip(7), dst: len(pkt), wantErr: ErrAuth},
		{name: "IV", aead: aead, pkt: flip(15), dst: len(pkt), wantErr: ErrAuth},
		{name: "VNI", aead: aead, pkt: flip(18), dst: len(pkt), wantErr: ErrAuth},
		{name: "VNI flags", aead: aead, pkt: flip(19), dst: len(pkt), wantErr: ErrAuth},
		{name: "seq", aead: aead, pkt: flip(23), dst: len(pkt), wantErr: ErrAuth},
		{name: "ciphertext", aead: aead, pkt: flip(PrefixLen + 5), dst: len(pkt), wantErr: ErrAuth},
		{name: "ICV", aead: aead, pkt: flip(len(pkt) - 1), dst: len(pkt), wantErr: ErrAuth},
		{name: "other key", aead: testAEAD(t, AESGCM256), pkt: pkt, dst: len(pkt), wantErr: ErrAuth},
		{name: "short", aead: aead, pkt: pkt[:Overhead-1], dst: len(pkt), wantErr: ErrShort},
		{name: "next header mismatch", aead: aead, pkt: mismatch, dst: len(pkt), wantErr: ErrNextHdr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(tc.aead, make([]byte, tc.dst), tc.pkt); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Open: got %v, want %v", err, tc.wantErr)
			}
			if _, err := OpenInPlace(tc.aead, bytes.Clone(tc.pkt)); !errors.Is(err, tc.wantErr) {
				t.Fatalf("OpenInPlace: got %v, want %v", err, tc.wantErr)
			}
		})
	}
	if _, err := Open(aead, make([]byte, len(inner)-1), pkt); !errors.Is(err, ErrBuffer) {
		t.Fatalf("Open with small dst: got %v, want %v", err, ErrBuffer)
	}
}

func TestPacketLimit(t *testing.T) {
	cases := []struct {
		mtu  int
		want uint32
	}{
		{0, 1 << 31},
		{1280, 1 << 31},
		{1500, 1 << 31},
		{2048, 1 << 31}, // 128 blocks: 2^38 / 2^7 = 2^31.
		{2049, (1 << 38) / 129},
		{9000, (1 << 38) / 563},
		{65535, (1 << 38) / 4096},
	}
	for _, tc := range cases {
		if got := PacketLimit(tc.mtu); got != tc.want {
			t.Errorf("PacketLimit(%d) = %d, want %d", tc.mtu, got, tc.want)
		}
	}
}

func TestNewAEAD(t *testing.T) {
	for _, n := range []int{0, 15, 24, 33} {
		if _, err := NewAEAD(make([]byte, n)); err == nil {
			t.Errorf("NewAEAD accepted a %d-byte key", n)
		}
	}
}

// TestNoAllocs checks that the per-packet functions do not allocate.
func TestNoAllocs(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	h := Header{SPI: 1, VNI: 3, Flags: FlagSeq}
	inner := testInner(4, 1280)
	pkt := make([]byte, len(inner)+Overhead)
	if _, err := Seal(aead, h, pkt, inner); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(pkt))
	buf := make([]byte, 64+len(pkt))
	cases := []struct {
		name string
		fn   func()
	}{
		{"ParseHeader", func() { _, _ = ParseHeader(pkt) }},
		{"Seal", func() { _, _ = Seal(aead, h, dst, inner) }},
		{"Open", func() { _, _ = Open(aead, dst, pkt) }},
		{"SealInPlace+OpenInPlace", func() {
			copy(buf[64:], inner)
			start, n, _ := SealInPlace(aead, h, buf, 64, len(inner))
			_, _ = OpenInPlace(aead, buf[start:start+n])
		}},
	}
	for _, tc := range cases {
		if a := testing.AllocsPerRun(100, tc.fn); a != 0 {
			t.Errorf("%s: %v allocs per run, want 0", tc.name, a)
		}
	}
}

// FuzzSealOpen checks that in-place and cross-buffer sealing give the same
// bytes, that both open paths give back the inner packet, and that a one-bit
// change anywhere in the packet fails.
func FuzzSealOpen(f *testing.F) {
	f.Add([]byte{0x45, 1, 2, 3}, false, uint32(1), uint64(1), uint32(7), uint8(FlagSeq), uint32(1), uint16(0))
	f.Add(testInner(6, 1280), true, uint32(0x9a345678), uint64(1<<63), uint32(MaxVNI), uint8(0xff), uint32(1<<31), uint16(900))
	aeads := [2]cipher.AEAD{testAEAD(f, AESGCM128), testAEAD(f, AESGCM256)}
	f.Fuzz(func(t *testing.T, inner []byte, v1 bool, spi uint32, iv uint64, vni uint32, flags uint8, seq uint32, bit uint16) {
		if _, ok := nextHdr(inner); !ok || ReservedSPI(spi) || vni > MaxVNI {
			return
		}
		v := AESGCM128
		if v1 {
			v = AESGCM256
		}
		aead := aeads[v]
		pkt := sealBoth(t, aead, Header{Version: v, SPI: spi, IV: iv, VNI: vni, Flags: flags, Seq: seq}, inner)
		if _, err := ParseHeader(pkt); err != nil {
			t.Fatalf("ParseHeader of a sealed packet: %v", err)
		}
		openBoth(t, aead, pkt, inner)

		i := int(bit) % (len(pkt) * 8)
		pkt[i/8] ^= 1 << (i % 8)
		if _, err := Open(aead, make([]byte, len(pkt)), pkt); err == nil {
			t.Fatalf("Open accepted a packet with bit %d changed", i)
		}
	})
}

func BenchmarkParseHeader(b *testing.B) {
	pkt := make([]byte, 1280+Overhead)
	(&Header{NextHdr: NextHdrV4, SPI: 1}).put(pkt)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseHeader(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, v := range []Version{AESGCM128, AESGCM256} {
		for _, n := range []int{64, 1280, 1400} {
			aead := testAEAD(b, v)
			h := Header{Version: v, SPI: 1, VNI: 3, Flags: FlagSeq}
			inner := testInner(4, n)
			b.Run(fmt.Sprintf("v%d/%d/cross", v, n), func(b *testing.B) {
				dst := make([]byte, n+Overhead)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					h.Seq++
					h.IV++
					if _, err := Seal(aead, h, dst, inner); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(fmt.Sprintf("v%d/%d/inplace", v, n), func(b *testing.B) {
				buf := make([]byte, PrefixLen+n+ICVLen)
				copy(buf[PrefixLen:], inner)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					h.Seq++
					h.IV++
					buf[PrefixLen] = inner[0] // Seal wrote ciphertext over it.
					if _, _, err := SealInPlace(aead, h, buf, PrefixLen, n); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, v := range []Version{AESGCM128, AESGCM256} {
		for _, n := range []int{64, 1280, 1400} {
			aead := testAEAD(b, v)
			inner := testInner(4, n)
			pkt := make([]byte, n+Overhead)
			if _, err := Seal(aead, Header{Version: v, SPI: 1, VNI: 3, Flags: FlagSeq}, pkt, inner); err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("v%d/%d/cross", v, n), func(b *testing.B) {
				dst := make([]byte, n)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := Open(aead, dst, pkt); err != nil {
						b.Fatal(err)
					}
				}
			})
			// OpenInPlace writes plaintext over the ciphertext, so each loop
			// opens a fresh copy. The copy is in the time.
			b.Run(fmt.Sprintf("v%d/%d/inplace", v, n), func(b *testing.B) {
				buf := make([]byte, len(pkt))
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					copy(buf, pkt)
					if _, err := OpenInPlace(aead, buf); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
