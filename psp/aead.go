// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Go's GCM lets dst alias src only at the same start (exact overlap), so the
// in-place functions seal and open the inner packet onto itself. The header
// goes in the headroom before it and the ICV in the tailroom after it.

// NewAEAD returns AES-GCM for an SA key: 16 bytes (v0) or 32 bytes (v1).
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("psp: SA key must be 16 or 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// PacketLimit returns how many packets one SA can carry with an inner MTU:
// min(2^31, 2^38 / ceil(MTU / 16)). Sequence numbers 0 to limit-1 are valid.
func PacketLimit(mtu int) uint32 {
	blocks := uint64(max(mtu+15, 16) / 16)
	return uint32(min(1<<31, (1<<38)/blocks))
}

// Seal writes the PSP packet for the inner IP packet to dst and returns its
// length, len(inner)+Overhead. dst must not overlap inner. Seal sets NextHdr
// from the inner packet and ignores h.NextHdr.
func Seal(aead cipher.AEAD, h Header, dst, inner []byte) (int, error) {
	if len(dst) < len(inner)+Overhead {
		return 0, ErrBuffer
	}
	if err := h.prepare(inner); err != nil {
		return 0, err
	}
	h.put(dst)
	aead.Seal(dst[PrefixLen:PrefixLen], dst[nonceOff:HeaderLen], inner, dst[:PrefixLen])
	return len(inner) + Overhead, nil
}

// SealPSP is Seal for a payload that is a whole PSP packet, as a trunk SA
// carries it. It sets NextHdr to NextHdrPSP and does not read the payload.
func SealPSP(aead cipher.AEAD, h Header, dst, pkt []byte) (int, error) {
	if len(dst) < len(pkt)+Overhead {
		return 0, ErrBuffer
	}
	h.NextHdr = NextHdrPSP
	if err := h.check(); err != nil {
		return 0, err
	}
	h.put(dst)
	aead.Seal(dst[PrefixLen:PrefixLen], dst[nonceOff:HeaderLen], pkt, dst[:PrefixLen])
	return len(pkt) + Overhead, nil
}

// SealInPlace encrypts the inner IP packet buf[off:off+n] in place. The header
// goes in the PrefixLen bytes before off and the ICV in the ICVLen bytes after
// the packet. It returns the start and the length of the PSP packet in buf.
func SealInPlace(aead cipher.AEAD, h Header, buf []byte, off, n int) (int, int, error) {
	if off < PrefixLen || n < 0 || n > len(buf)-off-ICVLen {
		return 0, 0, ErrBuffer
	}
	inner := buf[off : off+n]
	if err := h.prepare(inner); err != nil {
		return 0, 0, err
	}
	start := off - PrefixLen
	h.put(buf[start:off])
	aead.Seal(inner[:0], buf[start+nonceOff:start+HeaderLen], inner, buf[start:off])
	return start, n + Overhead, nil
}

// Open decrypts the PSP packet pkt to dst and returns the length of the inner
// packet. Call ParseHeader on pkt first. dst must not overlap pkt.
func Open(aead cipher.AEAD, dst, pkt []byte) (int, error) {
	if len(pkt) < Overhead {
		return 0, ErrShort
	}
	if len(dst) < len(pkt)-Overhead {
		return 0, ErrBuffer
	}
	inner, err := aead.Open(dst[:0], pkt[nonceOff:HeaderLen], pkt[PrefixLen:], pkt[:PrefixLen])
	if err != nil {
		return 0, ErrAuth
	}
	if nh, ok := nextHdr(inner); !ok || nh != pkt[0] {
		return 0, ErrNextHdr
	}
	return len(inner), nil
}

// OpenInPlace decrypts the PSP packet pkt in place and returns the inner
// packet, pkt[PrefixLen:len(pkt)-ICVLen]. Call ParseHeader on pkt first.
func OpenInPlace(aead cipher.AEAD, pkt []byte) ([]byte, error) {
	if len(pkt) < Overhead {
		return nil, ErrShort
	}
	ct := pkt[PrefixLen:]
	inner, err := aead.Open(ct[:0], pkt[nonceOff:HeaderLen], ct, pkt[:PrefixLen])
	if err != nil {
		return nil, ErrAuth
	}
	if nh, ok := nextHdr(inner); !ok || nh != pkt[0] {
		return nil, ErrNextHdr
	}
	return inner, nil
}

// OpenTrunkInPlace is OpenInPlace for a packet of a trunk SA, after
// ParseTrunkHeader. It does not read a NextHdrPSP payload.
func OpenTrunkInPlace(aead cipher.AEAD, pkt []byte) ([]byte, error) {
	if len(pkt) < Overhead {
		return nil, ErrShort
	}
	ct := pkt[PrefixLen:]
	payload, err := aead.Open(ct[:0], pkt[nonceOff:HeaderLen], ct, pkt[:PrefixLen])
	if err != nil {
		return nil, ErrAuth
	}
	if pkt[0] == NextHdrPSP {
		return payload, nil
	}
	if nh, ok := nextHdr(payload); !ok || nh != pkt[0] {
		return nil, ErrNextHdr
	}
	return payload, nil
}

// prepare sets h.NextHdr from the inner packet and checks h.
func (h *Header) prepare(inner []byte) error {
	nh, ok := nextHdr(inner)
	if !ok {
		return ErrNextHdr
	}
	h.NextHdr = nh
	return h.check()
}
