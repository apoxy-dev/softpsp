// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"crypto/cipher"
	"fmt"
	"sync/atomic"

	"github.com/apoxy-dev/softpsp/psp"
)

// TxSA is a transmit SA that a receiver gave to this sender. Seal can run on
// many goroutines at once.
type TxSA struct {
	spi     uint32
	vni     uint32
	version psp.Version
	limit   uint32
	aead    cipher.AEAD
	next    atomic.Uint64 // Next sequence number. The IV has the same value.
}

// NewTxSA returns a transmit SA. The key length selects the version: 16 bytes
// for AES-GCM-128, 32 bytes for AES-GCM-256. The inner MTU sets the packet limit.
func NewTxSA(spi uint32, key []byte, vni uint32, mtu int) (*TxSA, error) {
	switch {
	case psp.ReservedSPI(spi):
		return nil, psp.ErrSPI
	case vni > psp.MaxVNI:
		return nil, psp.ErrVNI
	case mtu <= 0:
		return nil, fmt.Errorf("engine: MTU must be positive, got %d", mtu)
	}
	aead, err := psp.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	v := psp.AESGCM128
	if len(key) == psp.AESGCM256.KeyLen() {
		v = psp.AESGCM256
	}
	return &TxSA{spi: spi, vni: vni, version: v, limit: psp.PacketLimit(mtu), aead: aead}, nil
}

// SPI returns the SPI of the SA.
func (s *TxSA) SPI() uint32 { return s.spi }

// Seal encrypts the inner IP packet to dst with the next sequence number and
// returns the PSP packet length. It returns ErrLimit when the SA has no
// sequence numbers left. A sequence number is never used twice.
func (s *TxSA) Seal(dst, inner []byte) (int, error) {
	seq, err := s.Reserve()
	if err != nil {
		return 0, err
	}
	return s.SealSeq(seq, dst, inner)
}

// Reserve takes the next sequence number for SealSeq. Use it when the seals
// run on many goroutines but the packets go out in Reserve order, so that
// the replay window of the receiver sees them in order.
func (s *TxSA) Reserve() (uint64, error) {
	seq := s.next.Add(1) - 1
	if seq >= uint64(s.limit) {
		return 0, ErrLimit
	}
	return seq, nil
}

// SealSeq is Seal with the sequence number seq from Reserve.
func (s *TxSA) SealSeq(seq uint64, dst, inner []byte) (int, error) {
	h := psp.Header{Version: s.version, SPI: s.spi, IV: seq, VNI: s.vni, Flags: psp.FlagSeq, Seq: uint32(seq)}
	return psp.Seal(s.aead, h, dst, inner)
}
