// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Go's GCM lets dst alias src only at the same start (exact overlap), so
// OpenInPlace opens the inner packet onto itself.

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
	if err := PutHeader(h, dst); err != nil {
		return 0, err
	}
	aead.Seal(dst[PrefixLen:PrefixLen], dst[nonceOff:HeaderLen], inner, dst[:PrefixLen])
	return len(inner) + Overhead, nil
}

// SealMessage is Seal for a message between relays (not an IP packet) on a
// trunk SA. It sets NextHdr to NextHdrMessage and does not read msg.
func SealMessage(aead cipher.AEAD, h Header, dst, msg []byte) (int, error) {
	if len(dst) < len(msg)+Overhead {
		return 0, ErrBuffer
	}
	h.NextHdr = NextHdrMessage
	if err := PutHeader(h, dst); err != nil {
		return 0, err
	}
	aead.Seal(dst[PrefixLen:PrefixLen], dst[nonceOff:HeaderLen], msg, dst[:PrefixLen])
	return len(msg) + Overhead, nil
}

// PutHeader writes h as the prefix (PSP header and VC) of a PSP packet to
// dst[:PrefixLen]. It writes h.NextHdr as given and does not read the payload.
func PutHeader(h Header, dst []byte) error {
	if len(dst) < PrefixLen {
		return ErrBuffer
	}
	if err := h.check(); err != nil {
		return err
	}
	h.put(dst)
	return nil
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

// CheckTrunk checks Next Header of the trunk packet pkt against its payload
// after the AEAD open. It does not read a NextHdrMessage payload.
func CheckTrunk(pkt, payload []byte) error {
	if len(pkt) == 0 {
		return ErrShort
	}
	if pkt[0] == NextHdrMessage {
		return nil
	}
	if nh, ok := nextHdr(payload); !ok || nh != pkt[0] {
		return ErrNextHdr
	}
	return nil
}

// prepare sets h.NextHdr from the inner packet.
func (h *Header) prepare(inner []byte) error {
	nh, ok := nextHdr(inner)
	if !ok {
		return ErrNextHdr
	}
	h.NextHdr = nh
	return nil
}
