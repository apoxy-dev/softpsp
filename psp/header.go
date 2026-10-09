// SPDX-License-Identifier: AGPL-3.0-only

package psp

import (
	"encoding/binary"
	"errors"
)

// A tunnel-mode PSP packet is the UDP payload. All fields are big endian.
//
//	off len
//	0   1   Next Header: 4 (IPv4) or 41 (IPv6)
//	1   1   Hdr Ext Len: 2 (IV and VC, in 8-byte units)
//	2   1   R (2 bits), Crypt Offset (6 bits): 2, so the VC is in clear
//	3   1   S, D, Version (4 bits), V, 1: 0x03 for v0, 0x07 for v1
//	4   4   SPI
//	8   8   IV
//	16  4   VNI word: VNI (24 bits), then 8 flag bits
//	20  4   Sequence number
//	24  n   Inner IP packet, encrypted
//	24+n 16 ICV
//
// The AAD is bytes 0-23 and the AES-GCM nonce is SPI || IV (bytes 4-15).
//
// On a trunk SA the VNI field holds a tag from the sender, and Next Header 63
// means that the payload is a whole PSP packet.
const (
	HeaderLen = 16                // PSP header up to and including the IV.
	VCLen     = 8                 // Virtualization cookie: VNI word and sequence number.
	PrefixLen = HeaderLen + VCLen // Bytes before the inner packet. Also the AAD.
	ICVLen    = 16                // AES-GCM tag.
	Overhead  = PrefixLen + ICVLen
	MaxVNI    = 1<<24 - 1
	NextHdrV4 = 4  // Next Header for an inner IPv4 packet.
	NextHdrV6 = 41 // Next Header for an inner IPv6 packet.
	// NextHdrPSP is the Next Header for a whole PSP packet as the payload, on
	// a trunk SA only. Below 64, a socket with QUIC reads it as not QUIC.
	NextHdrPSP = 63

	// FlagSeq is flag S of the VNI word: the VC carries a 32-bit sequence number.
	FlagSeq uint8 = 0x80
)

const (
	nonceOff = 4         // The nonce is bytes 4-15: SPI || IV.
	extLenVC = 2         // Hdr Ext Len with a VC.
	cryptOff = VCLen / 4 // Crypt Offset that keeps only the VC in clear.
	offMask  = 0x3f      // Crypt Offset bits of byte 2. The R bits are ignored.
	bitDrop  = 0x40      // D bit of byte 3. The S bit (0x80) is ignored.
	bitVC    = 0x02      // V bit of byte 3.
	bitOne   = 0x01      // Always 1.
	verShift = 2         // Version is bits 5-2 of byte 3.
	verMask  = 0x0f
)

var (
	ErrShort   = errors.New("psp: packet too short")
	ErrBuffer  = errors.New("psp: buffer too small")
	ErrNextHdr = errors.New("psp: next header does not match an inner IPv4 or IPv6 packet")
	ErrHeader  = errors.New("psp: header is not tunnel mode with a VC in clear")
	ErrVersion = errors.New("psp: unsupported version")
	ErrDrop    = errors.New("psp: drop bit set")
	ErrSPI     = errors.New("psp: reserved SPI")
	ErrVNI     = errors.New("psp: VNI does not fit in 24 bits")
	ErrAuth    = errors.New("psp: authentication failed")
)

// Header is the PSP header and VC of a tunnel-mode packet.
type Header struct {
	NextHdr uint8 // NextHdrV4, NextHdrV6 or NextHdrPSP. Seal takes it from the inner packet.
	Version Version
	SPI     uint32
	IV      uint64
	VNI     uint32 // 24 bits.
	Flags   uint8  // VNI word flags, for example FlagSeq.
	Seq     uint32
}

// ParseHeader reads and checks the header of the PSP packet pkt. It does not
// authenticate pkt. As the PSP spec says, it ignores the R bits and the S bit.
func ParseHeader(pkt []byte) (Header, error) {
	if len(pkt) < Overhead {
		return Header{}, ErrShort
	}
	if pkt[0] != NextHdrV4 && pkt[0] != NextHdrV6 {
		return Header{}, ErrNextHdr
	}
	if pkt[1] != extLenVC || pkt[2]&offMask != cryptOff || pkt[3]&(bitVC|bitOne) != bitVC|bitOne {
		return Header{}, ErrHeader
	}
	if pkt[3]&bitDrop != 0 {
		return Header{}, ErrDrop
	}
	v := Version(pkt[3] >> verShift & verMask)
	if !v.Valid() {
		return Header{}, ErrVersion
	}
	spi := binary.BigEndian.Uint32(pkt[4:8])
	if ReservedSPI(spi) {
		return Header{}, ErrSPI
	}
	w := binary.BigEndian.Uint32(pkt[16:20])
	return Header{
		NextHdr: pkt[0],
		Version: v,
		SPI:     spi,
		IV:      binary.BigEndian.Uint64(pkt[8:16]),
		VNI:     w >> 8,
		Flags:   uint8(w),
		Seq:     binary.BigEndian.Uint32(pkt[20:24]),
	}, nil
}

// ParseTrunkHeader is ParseHeader for a packet of a trunk SA. It also accepts
// NextHdrPSP.
func ParseTrunkHeader(pkt []byte) (Header, error) {
	if len(pkt) < Overhead || pkt[0] != NextHdrPSP {
		return ParseHeader(pkt)
	}
	// The other checks do not read Next Header, so ParseHeader does them on a
	// copy of the header with a value that it accepts.
	var b [Overhead]byte
	copy(b[:], pkt[:PrefixLen])
	b[0] = NextHdrV4
	h, err := ParseHeader(b[:])
	if err != nil {
		return Header{}, err
	}
	h.NextHdr = NextHdrPSP
	return h, nil
}

// check returns an error if Seal cannot send h.
func (h *Header) check() error {
	switch {
	case !h.Version.Valid():
		return ErrVersion
	case ReservedSPI(h.SPI):
		return ErrSPI
	case h.VNI > MaxVNI:
		return ErrVNI
	}
	return nil
}

// put writes h to b[:PrefixLen].
func (h *Header) put(b []byte) {
	_ = b[PrefixLen-1]
	b[0] = h.NextHdr
	b[1] = extLenVC
	b[2] = cryptOff
	b[3] = uint8(h.Version)<<verShift | bitVC | bitOne
	binary.BigEndian.PutUint32(b[4:8], h.SPI)
	binary.BigEndian.PutUint64(b[8:16], h.IV)
	binary.BigEndian.PutUint32(b[16:20], h.VNI<<8|uint32(h.Flags))
	binary.BigEndian.PutUint32(b[20:24], h.Seq)
}

// nextHdr returns the Next Header value for the inner IP packet.
func nextHdr(inner []byte) (uint8, bool) {
	if len(inner) == 0 {
		return 0, false
	}
	switch inner[0] >> 4 {
	case 4:
		return NextHdrV4, true
	case 6:
		return NextHdrV6, true
	}
	return 0, false
}
