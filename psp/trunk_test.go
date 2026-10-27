// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"testing"
)

// pspPayload returns a PSP packet for an n-byte inner packet, as a message.
func pspPayload(tb testing.TB, n int) []byte {
	tb.Helper()
	h := Header{Version: AESGCM256, SPI: 0x1234, IV: 9, VNI: 7, Flags: FlagSeq, Seq: 9}
	return sealPkt(tb, testAEAD(tb, AESGCM256), h, testInner(4, n))
}

// openTrunk opens a trunk packet in place as the relay does: ParseTrunkHeader,
// the AEAD open with the prefix as AAD, then CheckTrunk.
func openTrunk(aead cipher.AEAD, pkt []byte) ([]byte, error) {
	if _, err := ParseTrunkHeader(pkt); err != nil {
		return nil, err
	}
	ct := pkt[PrefixLen:]
	payload, err := aead.Open(ct[:0], pkt[nonceOff:HeaderLen], ct, pkt[:PrefixLen])
	if err != nil {
		return nil, ErrAuth
	}
	if err := CheckTrunk(pkt, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// TestParseTrunkHeader checks that only ParseTrunkHeader accepts NextHdrMessage,
// and that the two functions agree on all other packets.
func TestParseTrunkHeader(t *testing.T) {
	base := Header{NextHdr: NextHdrMessage, Version: AESGCM128, SPI: 0x9a345678, IV: 7, VNI: 0x123456, Flags: FlagSeq, Seq: 9}
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
		{name: "message", edit: func(p []byte) []byte { return p }, want: base, plain: ErrNextHdr},
		{name: "message v1", edit: func(p []byte) []byte { p[3] = 0x07; return p },
			want: Header{NextHdr: NextHdrMessage, Version: AESGCM256, SPI: base.SPI, IV: 7, VNI: base.VNI, Flags: FlagSeq, Seq: 9}, plain: ErrNextHdr},
		{name: "empty payload", edit: func(p []byte) []byte { return p[:Overhead] }, want: base, plain: ErrNextHdr},
		{name: "inner IPv4", edit: func(p []byte) []byte { p[0] = NextHdrV4; return p }, want: with(NextHdrV4)},
		{name: "inner IPv6", edit: func(p []byte) []byte { p[0] = NextHdrV6; return p }, want: with(NextHdrV6)},
		{name: "short", edit: func(p []byte) []byte { return p[:Overhead-1] }, wantErr: ErrShort},
		{name: "transport mode", edit: func(p []byte) []byte { p[0] = 17; return p }, wantErr: ErrNextHdr},
		{name: "next header 62", edit: func(p []byte) []byte { p[0] = NextHdrMessage - 1; return p }, wantErr: ErrNextHdr},
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

// TestSealMessage seals a message between relays. The trunk open path gives it
// back; the IP open code refuses it.
func TestSealMessage(t *testing.T) {
	for _, v := range []Version{AESGCM128, AESGCM256} {
		for _, n := range []int{1, 60, 1280, 1372} {
			t.Run(fmt.Sprintf("v%d/%d", v, n), func(t *testing.T) {
				aead := testAEAD(t, v)
				payload := pspPayload(t, n)
				h := Header{Version: v, SPI: 0x80000001, IV: 5, VNI: 0xabcdef, Flags: FlagSeq, Seq: 5}
				pkt := make([]byte, len(payload)+Overhead)
				m, err := SealMessage(aead, h, pkt, payload)
				if err != nil || m != len(pkt) {
					t.Fatalf("SealMessage: %d, %v, want %d", m, err, len(pkt))
				}
				got, err := ParseTrunkHeader(pkt)
				h.NextHdr = NextHdrMessage
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
				out, err := openTrunk(aead, pkt)
				if err != nil || !bytes.Equal(out, payload) {
					t.Fatalf("openTrunk: %v\n got %x\nwant %x", err, out, payload)
				}
			})
		}
	}
}

// TestTrunkNextHdrChange changes Next Header. ParseTrunkHeader accepts each
// new value, and openTrunk refuses the packet, because the prefix is the AAD.
func TestTrunkNextHdrChange(t *testing.T) {
	aead := testAEAD(t, AESGCM128)
	h := Header{SPI: 1, IV: 1, VNI: 0x00a5c3, Flags: FlagSeq, Seq: 1}
	payload := pspPayload(t, 60)
	msg := make([]byte, len(payload)+Overhead)
	if _, err := SealMessage(aead, h, msg, payload); err != nil {
		t.Fatal(err)
	}
	inner := testInner(6, 64)
	ip := sealPkt(t, aead, h, inner)
	cases := []struct {
		name    string
		pkt     []byte
		nh      uint8
		want    []byte
		wantErr error
	}{
		{name: "message", pkt: msg, nh: NextHdrMessage, want: payload},
		{name: "IPv6 packet", pkt: ip, nh: NextHdrV6, want: inner},
		{name: "message as an IPv4 packet", pkt: msg, nh: NextHdrV4, wantErr: ErrAuth},
		// CheckTrunk does not read a message payload: only the AEAD refuses it.
		{name: "IPv6 packet as a message", pkt: ip, nh: NextHdrMessage, wantErr: ErrAuth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := bytes.Clone(tc.pkt)
			pkt[0] = tc.nh
			got, err := openTrunk(aead, pkt)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("openTrunk: got %v, want %v", err, tc.wantErr)
			}
			if err == nil && !bytes.Equal(got, tc.want) {
				t.Fatalf("payload\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

func TestSealMessageErrors(t *testing.T) {
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
			if _, err := SealMessage(aead, tc.h, make([]byte, tc.dst), payload); !errors.Is(err, tc.wantErr) {
				t.Fatalf("SealMessage: got %v, want %v", err, tc.wantErr)
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
	cases := []struct {
		name string
		fn   func()
	}{
		{"SealMessage", func() { _, _ = SealMessage(aead, h, pkt, payload) }},
		{"ParseTrunkHeader", func() { _, _ = ParseTrunkHeader(pkt) }},
		{"CheckTrunk", func() { _ = CheckTrunk(pkt, payload) }},
	}
	for _, tc := range cases {
		if a := testing.AllocsPerRun(100, tc.fn); a != 0 {
			t.Errorf("%s: %v allocs per run, want 0", tc.name, a)
		}
	}
}

// FuzzParseTrunkHeader checks that the two parse functions give the same
// result for each packet, except that only ParseTrunkHeader accepts NextHdrMessage.
func FuzzParseTrunkHeader(f *testing.F) {
	p := make([]byte, Overhead+20)
	(&Header{NextHdr: NextHdrMessage, SPI: 1, VNI: 5, Flags: FlagSeq, Seq: 1}).put(p)
	f.Add(p)
	f.Add(p[:Overhead])
	f.Add(make([]byte, Overhead))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		got, err := ParseTrunkHeader(pkt)
		if len(pkt) < Overhead || pkt[0] != NextHdrMessage {
			if want, wantErr := ParseHeader(pkt); got != want || err != wantErr {
				t.Fatalf("got %+v, %v; ParseHeader gave %+v, %v", got, err, want, wantErr)
			}
			return
		}
		if _, plainErr := ParseHeader(pkt); plainErr != ErrNextHdr {
			t.Fatalf("ParseHeader of a NextHdrMessage packet: %v", plainErr)
		}
		// With Next Header 4, the same bytes must give the same result.
		v4 := bytes.Clone(pkt)
		v4[0] = NextHdrV4
		want, wantErr := ParseHeader(v4)
		want.NextHdr = NextHdrMessage
		if err != wantErr || (err == nil && got != want) {
			t.Fatalf("got %+v, %v, want %+v, %v", got, err, want, wantErr)
		}
	})
}
