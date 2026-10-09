// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// pspPayload returns the PSP packet of an agent for an n-byte inner packet.
func pspPayload(tb testing.TB, n int) []byte {
	tb.Helper()
	h := Header{Version: AESGCM256, SPI: 0x1234, IV: 9, VNI: 7, Flags: FlagSeq, Seq: 9}
	return sealBoth(tb, testAEAD(tb, AESGCM256), h, testInner(4, n))
}

// TestParseTrunkHeader checks that only ParseTrunkHeader accepts NextHdrPSP,
// and that the two functions agree on all other packets.
func TestParseTrunkHeader(t *testing.T) {
	base := Header{NextHdr: NextHdrPSP, Version: AESGCM128, SPI: 0x9a345678, IV: 7, VNI: 0x123456, Flags: FlagSeq, Seq: 9}
	with := func(nh uint8) Header {
		h := base
		h.NextHdr = nh
		return h
	}
	cases := []struct {
		name    string
		edit    func(p []byte) []byte
		want    Header
		wantErr error
		plain   error // ParseHeader error, if it is not wantErr.
	}{
		{name: "PSP packet", edit: func(p []byte) []byte { return p }, want: base, plain: ErrNextHdr},
		{name: "PSP packet v1", edit: func(p []byte) []byte { p[3] = 0x07; return p },
			want: Header{NextHdr: NextHdrPSP, Version: AESGCM256, SPI: base.SPI, IV: 7, VNI: base.VNI, Flags: FlagSeq, Seq: 9}, plain: ErrNextHdr},
		{name: "empty payload", edit: func(p []byte) []byte { return p[:Overhead] }, want: base, plain: ErrNextHdr},
		{name: "inner IPv4", edit: func(p []byte) []byte { p[0] = NextHdrV4; return p }, want: with(NextHdrV4)},
		{name: "inner IPv6", edit: func(p []byte) []byte { p[0] = NextHdrV6; return p }, want: with(NextHdrV6)},
		{name: "short", edit: func(p []byte) []byte { return p[:Overhead-1] }, wantErr: ErrShort},
		{name: "transport mode", edit: func(p []byte) []byte { p[0] = 17; return p }, wantErr: ErrNextHdr},
		{name: "next header 62", edit: func(p []byte) []byte { p[0] = NextHdrPSP - 1; return p }, wantErr: ErrNextHdr},
		{name: "no VC", edit: func(p []byte) []byte { p[1] = 1; return p }, wantErr: ErrHeader, plain: ErrNextHdr},
		{name: "crypt offset 3", edit: func(p []byte) []byte { p[2] = 3; return p }, wantErr: ErrHeader, plain: ErrNextHdr},
		{name: "D bit", edit: func(p []byte) []byte { p[3] |= bitDrop; return p }, wantErr: ErrDrop, plain: ErrNextHdr},
		{name: "GMAC version", edit: func(p []byte) []byte { p[3] = 2<<verShift | bitVC | bitOne; return p }, wantErr: ErrVersion, plain: ErrNextHdr},
		{name: "SPI 0", edit: func(p []byte) []byte { copy(p[4:8], []byte{0, 0, 0, 0}); return p }, wantErr: ErrSPI, plain: ErrNextHdr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, Overhead+20)
			base.put(p)
			p = tc.edit(p)
			before := bytes.Clone(p)
			got, err := ParseTrunkHeader(p)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseTrunkHeader: got %v, want %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("header\n got %+v\nwant %+v", got, tc.want)
			}
			if !bytes.Equal(p, before) {
				t.Fatal("ParseTrunkHeader changed the packet")
			}
			plain := tc.plain
			if plain == nil {
				plain = tc.wantErr
			}
			h, err := ParseHeader(p)
			if !errors.Is(err, plain) {
				t.Fatalf("ParseHeader: got %v, want %v", err, plain)
			}
			if err == nil && h != got {
				t.Fatalf("ParseHeader gave %+v, ParseTrunkHeader gave %+v", h, got)
			}
		})
	}

	got := make([]byte, PrefixLen)
	base.put(got)
	if want := unhex(t, "3f020203 9a345678 0000000000000007 12345680 00000009"); !bytes.Equal(got, want) {
		t.Fatalf("header bytes\n got %x\nwant %x", got, want)
	}
}

// TestSealPSP seals a whole PSP packet as the payload. OpenTrunkInPlace gives
// back the same bytes, and the functions of an inner IP packet refuse it.
func TestSealPSP(t *testing.T) {
	for _, v := range []Version{AESGCM128, AESGCM256} {
		// An inner MTU of 1372 gives the largest packet that a relay socket
		// reads: 1452 bytes.
		for _, n := range []int{1, 60, 1280, 1372} {
			t.Run(fmt.Sprintf("v%d/%d", v, n), func(t *testing.T) {
				aead := testAEAD(t, v)
				payload := pspPayload(t, n)
				h := Header{Version: v, SPI: 0x80000001, IV: 5, VNI: 0xabcdef, Flags: FlagSeq, Seq: 5}
				pkt := make([]byte, len(payload)+Overhead)
				m, err := SealPSP(aead, h, pkt, payload)
				if err != nil || m != len(pkt) {
					t.Fatalf("SealPSP: %d, %v, want %d", m, err, len(pkt))
				}
				got, err := ParseTrunkHeader(pkt)
				h.NextHdr = NextHdrPSP
				if err != nil || got != h {
					t.Fatalf("ParseTrunkHeader: %+v, %v, want %+v", got, err, h)
				}
				// The packet authenticates, but its payload is not an IP packet.
				if _, err := Open(aead, make([]byte, len(pkt)), pkt); !errors.Is(err, ErrNextHdr) {
					t.Fatalf("Open: got %v, want %v", err, ErrNextHdr)
				}
				if _, err := OpenInPlace(aead, bytes.Clone(pkt)); !errors.Is(err, ErrNextHdr) {
					t.Fatalf("OpenInPlace: got %v, want %v", err, ErrNextHdr)
				}
				out, err := OpenTrunkInPlace(aead, pkt)
				if err != nil || !bytes.Equal(out, payload) {
					t.Fatalf("OpenTrunkInPlace: %v\n got %x\nwant %x", err, out, payload)
				}
				if _, err := ParseHeader(out); err != nil {
					t.Fatalf("ParseHeader of the payload: %v", err)
				}
			})
		}
	}
}

func TestSealPSPErrors(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	payload := pspPayload(t, 60)
	cases := []struct {
		name    string
		h       Header
		dst     int
		wantErr error
	}{
		{"version 2", Header{Version: 2, SPI: 1}, len(payload) + Overhead, ErrVersion},
		{"SPI 0", Header{}, len(payload) + Overhead, ErrSPI},
		{"tag too big", Header{SPI: 1, VNI: MaxVNI + 1}, len(payload) + Overhead, ErrVNI},
		{"small dst", Header{SPI: 1}, len(payload) + Overhead - 1, ErrBuffer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SealPSP(aead, tc.h, make([]byte, tc.dst), payload); !errors.Is(err, tc.wantErr) {
				t.Fatalf("SealPSP: got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestOpenTrunkInPlace opens the packets of a trunk SA: a PSP packet or an
// inner IP packet as the payload. A change to one bit of the tag fails the ICV.
func TestOpenTrunkInPlace(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	h := Header{SPI: 1, IV: 1, VNI: 0x00a5c3, Flags: FlagSeq, Seq: 1}
	payload := pspPayload(t, 60)
	fwd := make([]byte, len(payload)+Overhead)
	if _, err := SealPSP(aead, h, fwd, payload); err != nil {
		t.Fatal(err)
	}
	inner := testInner(6, 64)
	ip := sealBoth(t, aead, h, inner)

	// An inner IPv4 packet under Next Header 41.
	mismatch := make([]byte, len(ip))
	(&Header{NextHdr: NextHdrV6, SPI: 1, IV: 2}).put(mismatch)
	aead.Seal(mismatch[PrefixLen:PrefixLen], mismatch[nonceOff:HeaderLen], testInner(4, 64), mismatch[:PrefixLen])

	edit := func(p []byte, f func([]byte)) []byte {
		p = bytes.Clone(p)
		f(p)
		return p
	}
	type openCase struct {
		name    string
		pkt     []byte
		want    []byte
		wantErr error
	}
	cases := []openCase{
		{name: "PSP packet", pkt: fwd, want: payload},
		{name: "inner IP packet", pkt: ip, want: inner},
		{name: "PSP packet as an IP packet", pkt: edit(fwd, func(p []byte) { p[0] = NextHdrV4 }), wantErr: ErrAuth},
		{name: "IP packet as a PSP packet", pkt: edit(ip, func(p []byte) { p[0] = NextHdrPSP }), wantErr: ErrAuth},
		{name: "other tag", pkt: edit(fwd, func(p []byte) { copy(p[16:19], []byte{0, 0, 1}) }), wantErr: ErrAuth},
		{name: "tag 0", pkt: edit(ip, func(p []byte) { copy(p[16:19], []byte{0, 0, 0}) }), wantErr: ErrAuth},
		{name: "seq", pkt: edit(fwd, func(p []byte) { p[23] ^= 1 }), wantErr: ErrAuth},
		{name: "payload", pkt: edit(fwd, func(p []byte) { p[PrefixLen+4] ^= 1 }), wantErr: ErrAuth},
		{name: "ICV", pkt: edit(fwd, func(p []byte) { p[len(p)-1] ^= 1 }), wantErr: ErrAuth},
		{name: "short", pkt: fwd[:Overhead-1], wantErr: ErrShort},
		{name: "next header mismatch", pkt: mismatch, wantErr: ErrNextHdr},
	}
	for bit := range 24 {
		pkt := edit(fwd, func(p []byte) { p[16+bit/8] ^= 0x80 >> (bit % 8) })
		cases = append(cases, openCase{name: fmt.Sprintf("tag bit %d", bit), pkt: pkt, wantErr: ErrAuth})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OpenTrunkInPlace(aead, bytes.Clone(tc.pkt))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("OpenTrunkInPlace: got %v, want %v", err, tc.wantErr)
			}
			if err == nil && !bytes.Equal(got, tc.want) {
				t.Fatalf("payload\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

// TestTrunkNoAllocs checks that the per-packet trunk functions do not allocate.
func TestTrunkNoAllocs(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	h := Header{SPI: 1, VNI: 3, Flags: FlagSeq}
	payload := pspPayload(t, 1280)
	pkt := make([]byte, len(payload)+Overhead)
	buf := make([]byte, len(pkt))
	cases := []struct {
		name string
		fn   func()
	}{
		{"SealPSP", func() { _, _ = SealPSP(aead, h, pkt, payload) }},
		{"ParseTrunkHeader", func() { _, _ = ParseTrunkHeader(pkt) }},
		{"OpenTrunkInPlace", func() {
			copy(buf, pkt)
			_, _ = OpenTrunkInPlace(aead, buf)
		}},
	}
	for _, tc := range cases {
		if a := testing.AllocsPerRun(100, tc.fn); a != 0 {
			t.Errorf("%s: %v allocs per run, want 0", tc.name, a)
		}
	}
}

// FuzzParseTrunkHeader checks that the two parse functions give the same
// result for each packet, except that only ParseTrunkHeader accepts NextHdrPSP.
func FuzzParseTrunkHeader(f *testing.F) {
	p := make([]byte, Overhead+20)
	(&Header{NextHdr: NextHdrPSP, SPI: 1, VNI: 5, Flags: FlagSeq, Seq: 1}).put(p)
	f.Add(p)
	f.Add(p[:Overhead])
	f.Add(make([]byte, Overhead))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		got, err := ParseTrunkHeader(pkt)
		if len(pkt) < Overhead || pkt[0] != NextHdrPSP {
			if want, wantErr := ParseHeader(pkt); got != want || err != wantErr {
				t.Fatalf("got %+v, %v; ParseHeader gave %+v, %v", got, err, want, wantErr)
			}
			return
		}
		if _, plainErr := ParseHeader(pkt); plainErr != ErrNextHdr {
			t.Fatalf("ParseHeader of a NextHdrPSP packet: %v", plainErr)
		}
		// With Next Header 4, the same bytes must give the same result.
		v4 := bytes.Clone(pkt)
		v4[0] = NextHdrV4
		want, wantErr := ParseHeader(v4)
		want.NextHdr = NextHdrPSP
		if err != wantErr || (err == nil && got != want) {
			t.Fatalf("got %+v, %v, want %+v, %v", got, err, want, wantErr)
		}
	})
}
