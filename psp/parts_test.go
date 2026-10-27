// SPDX-License-Identifier: AGPL-3.0-only

package psp_test

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
)

// nonceOff is the start of the nonce (SPI || IV) in the prefix.
const nonceOff = 4

// newAEAD returns the AEAD for an SA key of version v. Each seed gives a
// different key.
func newAEAD(t *testing.T, v psp.Version, seed byte) cipher.AEAD {
	t.Helper()
	key := make([]byte, v.KeyLen())
	for i := range key {
		key[i] = seed + byte(i)
	}
	aead, err := psp.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// ipPacket returns an n-byte packet that starts with the IP version nibble ipv.
func ipPacket(ipv, n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i * 3)
	}
	if n > 0 {
		p[0] = byte(ipv<<4 | 5)
	}
	return p
}

// seal makes a PSP packet as the relay does: PutHeader writes h in front of
// the payload, then AES-GCM seals the payload in place with the prefix as AAD.
func seal(t *testing.T, aead cipher.AEAD, h psp.Header, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, psp.PrefixLen+len(payload), len(payload)+psp.Overhead)
	body := pkt[psp.PrefixLen:]
	copy(body, payload)
	if err := psp.PutHeader(h, pkt); err != nil {
		t.Fatalf("PutHeader: %v", err)
	}
	return aead.Seal(pkt[:psp.PrefixLen], pkt[nonceOff:psp.HeaderLen], body, pkt[:psp.PrefixLen])
}

// openTrunk opens a trunk packet in place as the relay does: ParseTrunkHeader,
// the AEAD open with the prefix as AAD, then CheckTrunk.
func openTrunk(aead cipher.AEAD, pkt []byte) ([]byte, error) {
	if _, err := psp.ParseTrunkHeader(pkt); err != nil {
		return nil, err
	}
	ct := pkt[psp.PrefixLen:]
	payload, err := aead.Open(ct[:0], pkt[nonceOff:psp.HeaderLen], ct, pkt[:psp.PrefixLen])
	if err != nil {
		return nil, psp.ErrAuth
	}
	if err := psp.CheckTrunk(pkt, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// pspPacket returns a PSP packet. The tests use it as a message, which the
// trunk code does not read.
func pspPacket(t *testing.T) []byte {
	t.Helper()
	h := psp.Header{NextHdr: psp.NextHdrV6, Version: psp.AESGCM128, SPI: 3, IV: 4, VNI: 5, Seq: 6}
	return seal(t, newAEAD(t, psp.AESGCM128, 50), h, ipPacket(6, 80))
}

func withNextHdr(h psp.Header, nh uint8) psp.Header {
	h.NextHdr = nh
	return h
}

// TestPutOpen writes h with PutHeader and seals the payload. The parse code
// must give back h, and the open code the payload or its error.
func TestPutOpen(t *testing.T) {
	agent := pspPacket(t)
	v1 := psp.Header{Version: psp.AESGCM256, SPI: 1<<31 | 7, IV: 1<<63 | 9, VNI: psp.MaxVNI, Flags: psp.FlagSeq, Seq: 1<<32 - 1}
	v0 := psp.Header{Version: psp.AESGCM128, SPI: 12, IV: 34, VNI: 56, Seq: 78}

	openCopy := func(aead cipher.AEAD, pkt []byte) ([]byte, error) {
		dst := make([]byte, len(pkt))
		n, err := psp.Open(aead, dst, pkt)
		return dst[:n], err
	}
	type opener struct {
		name string
		open func(aead cipher.AEAD, pkt []byte) ([]byte, error)
	}
	ipOpens := []opener{{"Open", openCopy}, {"OpenInPlace", psp.OpenInPlace}}
	trunkOpens := []opener{{"openTrunk", openTrunk}}

	cases := []struct {
		name    string
		h       psp.Header
		payload []byte
		trunk   bool  // Read with ParseTrunkHeader and openTrunk.
		wantErr error // From the open code.
	}{
		{name: "IPv4 v1", h: withNextHdr(v1, psp.NextHdrV4), payload: ipPacket(4, 60)},
		{name: "IPv6 v0", h: withNextHdr(v0, psp.NextHdrV6), payload: ipPacket(6, 1400)},
		{name: "1-byte inner", h: withNextHdr(v0, psp.NextHdrV4), payload: ipPacket(4, 1)},
		{name: "IPv4 on a trunk SA", h: withNextHdr(v1, psp.NextHdrV4), payload: ipPacket(4, 60), trunk: true},
		{name: "IPv6 on a trunk SA", h: withNextHdr(v0, psp.NextHdrV6), payload: ipPacket(6, 60), trunk: true},
		{name: "message v1", h: withNextHdr(v1, psp.NextHdrMessage), payload: agent, trunk: true},
		{name: "message v0", h: withNextHdr(v0, psp.NextHdrMessage), payload: agent, trunk: true},
		{name: "empty message", h: withNextHdr(v0, psp.NextHdrMessage), trunk: true},
		// PutHeader does not read the payload. The open code finds the mismatch.
		{name: "NextHdr 41 with an IPv4 packet", h: withNextHdr(v1, psp.NextHdrV6), payload: ipPacket(4, 60), wantErr: psp.ErrNextHdr},
		{name: "NextHdr 41 with an IPv4 packet on a trunk SA", h: withNextHdr(v1, psp.NextHdrV6), payload: ipPacket(4, 60),
			trunk: true, wantErr: psp.ErrNextHdr},
		{name: "NextHdr 4 with a message", h: withNextHdr(v1, psp.NextHdrV4), payload: agent, trunk: true, wantErr: psp.ErrNextHdr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aead := newAEAD(t, tc.h.Version, 1)
			pkt := seal(t, aead, tc.h, tc.payload)

			parse, opens := psp.ParseHeader, ipOpens
			if tc.trunk {
				parse, opens = psp.ParseTrunkHeader, trunkOpens
			}
			// The parse code also rejects a wrong Hdr Ext Len, crypt offset or V bit.
			got, err := parse(pkt)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tc.h {
				t.Fatalf("header\n got %+v\nwant %+v", got, tc.h)
			}
			for _, o := range opens {
				payload, err := o.open(aead, bytes.Clone(pkt))
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("%s: got %v, want %v", o.name, err, tc.wantErr)
				}
				if err == nil && !bytes.Equal(payload, tc.payload) {
					t.Fatalf("%s payload\n got %x\nwant %x", o.name, payload, tc.payload)
				}
			}
		})
	}
}

// TestSealMessageNextHdr seals messages that look like IP packets. The parse
// code must give NextHdrMessage, and only the trunk open code accepts them.
func TestSealMessageNextHdr(t *testing.T) {
	aead := newAEAD(t, psp.AESGCM128, 1)
	h := psp.Header{NextHdr: psp.NextHdrV4, Version: psp.AESGCM128, SPI: 21, IV: 22, VNI: 23, Flags: psp.FlagSeq, Seq: 24}
	want := withNextHdr(h, psp.NextHdrMessage)
	cases := []struct {
		name string
		msg  []byte
	}{
		{name: "empty message", msg: nil},
		{name: "message that starts with 0x45", msg: ipPacket(4, 60)},
		{name: "message that starts with 0x65", msg: ipPacket(6, 60)},
		{name: "message that is a PSP packet", msg: pspPacket(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := make([]byte, len(tc.msg)+psp.Overhead)
			n, err := psp.SealMessage(aead, h, pkt, tc.msg)
			if err != nil || n != len(pkt) {
				t.Fatalf("SealMessage: %d, %v, want %d", n, err, len(pkt))
			}
			got, err := psp.ParseTrunkHeader(pkt)
			if err != nil || got != want {
				t.Fatalf("ParseTrunkHeader: %+v, %v, want %+v", got, err, want)
			}
			if _, err := psp.OpenInPlace(aead, bytes.Clone(pkt)); !errors.Is(err, psp.ErrNextHdr) {
				t.Fatalf("OpenInPlace: got %v, want %v", err, psp.ErrNextHdr)
			}
			msg, err := openTrunk(aead, pkt)
			if err != nil || !bytes.Equal(msg, tc.msg) {
				t.Fatalf("openTrunk: %v\n got %x\nwant %x", err, msg, tc.msg)
			}
		})
	}
}

// TestCheckTrunk gives CheckTrunk packets and payloads that openTrunk
// opened. A payload of a different packet must match the Next Header of pkt.
func TestCheckTrunk(t *testing.T) {
	aead := newAEAD(t, psp.AESGCM256, 1)
	h := psp.Header{Version: psp.AESGCM256, SPI: 9, IV: 10, VNI: 11, Flags: psp.FlagSeq, Seq: 12}
	open := func(nh uint8, payload []byte) ([]byte, []byte) {
		pkt := seal(t, aead, withNextHdr(h, nh), payload)
		opened, err := openTrunk(aead, pkt)
		if err != nil {
			t.Fatalf("openTrunk: %v", err)
		}
		return pkt, opened
	}
	v4, v4Payload := open(psp.NextHdrV4, ipPacket(4, 60))
	v6, v6Payload := open(psp.NextHdrV6, ipPacket(6, 60))
	msg, msgPayload := open(psp.NextHdrMessage, pspPacket(t))

	cases := []struct {
		name         string
		pkt, payload []byte
		wantErr      error
	}{
		{name: "IPv4", pkt: v4, payload: v4Payload},
		{name: "IPv6", pkt: v6, payload: v6Payload},
		{name: "message", pkt: msg, payload: msgPayload},
		{name: "NextHdrMessage with an IPv4 payload", pkt: msg, payload: v4Payload},
		{name: "NextHdrMessage with an empty payload", pkt: msg, payload: msgPayload[:0]},
		{name: "IPv4 with an IPv6 payload", pkt: v4, payload: v6Payload, wantErr: psp.ErrNextHdr},
		{name: "IPv6 with an IPv4 payload", pkt: v6, payload: v4Payload, wantErr: psp.ErrNextHdr},
		// The message is a PSP packet. Its first byte is not an IP version nibble.
		{name: "IPv4 with a message payload", pkt: v4, payload: msgPayload, wantErr: psp.ErrNextHdr},
		{name: "IPv4 with an empty payload", pkt: v4, payload: v4Payload[:0], wantErr: psp.ErrNextHdr},
		{name: "empty pkt", pkt: v4[:0], payload: v4Payload, wantErr: psp.ErrShort},
		{name: "nil pkt", wantErr: psp.ErrShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := psp.CheckTrunk(tc.pkt, tc.payload); !errors.Is(err, tc.wantErr) {
				t.Fatalf("CheckTrunk: got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestPutErrors checks the errors of PutHeader. When there is no error, the
// parse code must read h back from a dst of PrefixLen.
func TestPutErrors(t *testing.T) {
	good := psp.Header{NextHdr: psp.NextHdrV4, Version: psp.AESGCM128, SPI: 1, IV: 2, VNI: 3, Seq: 4}
	with := func(f func(h *psp.Header)) psp.Header {
		h := good
		f(&h)
		return h
	}
	cases := []struct {
		name string
		h    psp.Header
		dst  int
		want error
	}{
		{name: "NextHdr 4 in a dst of PrefixLen", h: good, dst: psp.PrefixLen},
		{name: "NextHdr 41 in a dst of PrefixLen", h: withNextHdr(good, psp.NextHdrV6), dst: psp.PrefixLen},
		{name: "NextHdr 63 in a dst of PrefixLen", h: withNextHdr(good, psp.NextHdrMessage), dst: psp.PrefixLen},
		{name: "dst shorter than PrefixLen", h: good, dst: psp.PrefixLen - 1, want: psp.ErrBuffer},
		{name: "empty dst", h: good, want: psp.ErrBuffer},
		{name: "NextHdr that is not 4, 41 or 63", h: withNextHdr(good, 17), dst: psp.PrefixLen, want: psp.ErrNextHdr},
		{name: "NextHdr 0", h: withNextHdr(good, 0), dst: psp.PrefixLen, want: psp.ErrNextHdr},
		{name: "NextHdr 62", h: withNextHdr(good, psp.NextHdrMessage-1), dst: psp.PrefixLen, want: psp.ErrNextHdr},
		{name: "NextHdr 64", h: withNextHdr(good, psp.NextHdrMessage+1), dst: psp.PrefixLen, want: psp.ErrNextHdr},
		{name: "SPI 0", h: with(func(h *psp.Header) { h.SPI = 0 }), dst: psp.PrefixLen, want: psp.ErrSPI},
		{name: "SPI with only the master key bit", h: with(func(h *psp.Header) { h.SPI = 1 << 31 }), dst: psp.PrefixLen, want: psp.ErrSPI},
		{name: "version 2", h: with(func(h *psp.Header) { h.Version = 2 }), dst: psp.PrefixLen, want: psp.ErrVersion},
		{name: "VNI over 24 bits", h: with(func(h *psp.Header) { h.VNI = psp.MaxVNI + 1 }), dst: psp.PrefixLen, want: psp.ErrVNI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, tc.dst)
			if err := psp.PutHeader(tc.h, dst); !errors.Is(err, tc.want) {
				t.Fatalf("PutHeader: got %v, want %v", err, tc.want)
			}
			if tc.want != nil {
				return
			}
			// The parse code needs room for an ICV after the prefix.
			got, err := psp.ParseTrunkHeader(append(dst, make([]byte, psp.ICVLen)...))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tc.h {
				t.Fatalf("header\n got %+v\nwant %+v", got, tc.h)
			}
		})
	}
}
