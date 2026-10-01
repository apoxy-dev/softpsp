// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"bytes"
	"errors"
	"testing"
)

// TestHeaderWireLayout pins the bytes that put writes.
func TestHeaderWireLayout(t *testing.T) {
	cases := []struct {
		name string
		h    Header
		want string
	}{
		{
			name: "v0 IPv4",
			h: Header{NextHdr: NextHdrV4, Version: AESGCM128, SPI: 0x9a345678, IV: 0x0102030405060708,
				VNI: 0x123456, Flags: FlagSeq, Seq: 0x0a0b0c0d},
			want: "04020203 9a345678 0102030405060708 12345680 0a0b0c0d",
		},
		{
			name: "v1 IPv6",
			h:    Header{NextHdr: NextHdrV6, Version: AESGCM256, SPI: 1, IV: 1, VNI: MaxVNI, Seq: 0xffffffff},
			want: "29020207 00000001 0000000000000001 ffffff00 ffffffff",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := make([]byte, PrefixLen)
			tc.h.put(got)
			if want := unhex(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("header bytes\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	base := Header{NextHdr: NextHdrV4, Version: AESGCM128, SPI: 0x9a345678, IV: 7, VNI: 0x123456, Flags: FlagSeq, Seq: 9}
	cases := []struct {
		name    string
		edit    func(p []byte) []byte
		want    Header
		wantErr error
	}{
		{name: "valid", edit: func(p []byte) []byte { return p }, want: base},
		{name: "IPv6 v1", edit: func(p []byte) []byte { p[0], p[3] = NextHdrV6, 0x07; return p },
			want: Header{NextHdr: NextHdrV6, Version: AESGCM256, SPI: base.SPI, IV: 7, VNI: base.VNI, Flags: FlagSeq, Seq: 9}},
		{name: "R bits ignored", edit: func(p []byte) []byte { p[2] |= 0xc0; return p }, want: base},
		{name: "S bit ignored", edit: func(p []byte) []byte { p[3] |= 0x80; return p }, want: base},
		{name: "other VNI flags", edit: func(p []byte) []byte { p[19] = 0x7f; return p },
			want: Header{NextHdr: NextHdrV4, Version: AESGCM128, SPI: base.SPI, IV: 7, VNI: base.VNI, Flags: 0x7f, Seq: 9}},
		{name: "empty inner", edit: func(p []byte) []byte { return p[:Overhead] }, want: base},
		{name: "short", edit: func(p []byte) []byte { return p[:Overhead-1] }, wantErr: ErrShort},
		{name: "transport mode", edit: func(p []byte) []byte { p[0] = 17; return p }, wantErr: ErrNextHdr},
		{name: "no VC", edit: func(p []byte) []byte { p[1] = 1; return p }, wantErr: ErrHeader},
		{name: "crypt offset 0", edit: func(p []byte) []byte { p[2] = 0; return p }, wantErr: ErrHeader},
		{name: "crypt offset 3", edit: func(p []byte) []byte { p[2] = 3; return p }, wantErr: ErrHeader},
		{name: "V bit clear", edit: func(p []byte) []byte { p[3] &^= bitVC; return p }, wantErr: ErrHeader},
		{name: "one bit clear", edit: func(p []byte) []byte { p[3] &^= bitOne; return p }, wantErr: ErrHeader},
		{name: "D bit", edit: func(p []byte) []byte { p[3] |= bitDrop; return p }, wantErr: ErrDrop},
		{name: "GMAC version", edit: func(p []byte) []byte { p[3] = 2<<verShift | bitVC | bitOne; return p }, wantErr: ErrVersion},
		{name: "version 15", edit: func(p []byte) []byte { p[3] = 15<<verShift | bitVC | bitOne; return p }, wantErr: ErrVersion},
		{name: "SPI 0", edit: func(p []byte) []byte { copy(p[4:8], []byte{0, 0, 0, 0}); return p }, wantErr: ErrSPI},
		{name: "SPI MSB only", edit: func(p []byte) []byte { copy(p[4:8], []byte{0x80, 0, 0, 0}); return p }, wantErr: ErrSPI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, Overhead+20)
			base.put(p)
			got, err := ParseHeader(tc.edit(p))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error: got %v, want %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("header\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// FuzzParseHeader checks that ParseHeader does not panic and that a header it
// accepts writes back to the same bytes, except the ignored R and S bits.
func FuzzParseHeader(f *testing.F) {
	p := make([]byte, Overhead+20)
	(&Header{NextHdr: NextHdrV4, SPI: 1, VNI: 5, Flags: FlagSeq, Seq: 1}).put(p)
	f.Add(p)
	f.Add(p[:Overhead])
	f.Add(make([]byte, Overhead))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		h, err := ParseHeader(pkt)
		if err != nil {
			return
		}
		if h.VNI > MaxVNI || !h.Version.Valid() || ReservedSPI(h.SPI) {
			t.Fatalf("parsed a header that Seal would not send: %+v", h)
		}
		got := make([]byte, PrefixLen)
		h.put(got)
		want := bytes.Clone(pkt[:PrefixLen])
		want[2] &= offMask
		want[3] &^= 0x80
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip\n got %x\nwant %x", got, want)
		}
	})
}
