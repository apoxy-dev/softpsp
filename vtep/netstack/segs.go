// SPDX-License-Identifier: AGPL-3.0-only

package netstack

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// maxSegHdr is the most bytes of IP and TCP headers that tcpSegs takes.
const maxSegHdr = 192

// tcpSegs cuts a TCP packet into packets with at most mss payload bytes, as TSO
// does. It writes the headers of each packet in pkt, before its payload and
// over the previous packet. Thus use each packet before the next call to next.
type tcpSegs struct {
	pkt    []byte
	hdr    [maxSegHdr]byte // The headers of pkt.
	ipLen  int
	hdrLen int
	mss    int
	off    int // Offset of the next payload in pkt.
	i      int // Index of the next packet.
	seq    uint32
	id     uint16
	pseudo uint16 // Pseudo-header checksum without the length.
	v4     bool
}

// init prepares to cut pkt, an IPv4 or IPv6 packet with ipLen bytes of IP
// headers and then a TCP header. An mss of 0 gives one packet. It returns
// false when pkt is not such a packet.
func (s *tcpSegs) init(pkt []byte, ipLen, mss int) bool {
	if len(pkt) < ipLen+header.TCPMinimumSize {
		return false
	}
	switch pkt[0] >> 4 {
	case header.IPv4Version:
		if ipLen != int(pkt[0]&0xf)*4 || ipLen < header.IPv4MinimumSize || pkt[9] != uint8(header.TCPProtocolNumber) {
			return false
		}
		s.v4 = true
		s.id = binary.BigEndian.Uint16(pkt[4:])
		s.pseudo = checksum.Checksum(pkt[12:20], 0)
	case header.IPv6Version:
		if ipLen < header.IPv6MinimumSize {
			return false
		}
		s.v4 = false
		s.pseudo = checksum.Checksum(pkt[8:40], 0)
	default:
		return false
	}
	tcpLen := int(pkt[ipLen+12]>>4) * 4
	if tcpLen < header.TCPMinimumSize || ipLen+tcpLen > min(len(pkt), maxSegHdr) {
		return false
	}
	s.pseudo = checksum.Combine(s.pseudo, uint16(header.TCPProtocolNumber))
	s.pkt, s.ipLen, s.hdrLen = pkt, ipLen, ipLen+tcpLen
	copy(s.hdr[:], pkt[:s.hdrLen])
	s.seq = binary.BigEndian.Uint32(pkt[ipLen+4:])
	s.mss = mss
	if mss <= 0 {
		s.mss = len(pkt) - s.hdrLen
	}
	s.off, s.i = s.hdrLen, 0
	return true
}

// next returns the next packet, or nil after the last one.
func (s *tcpSegs) next() []byte {
	if s.i > 0 && s.off >= len(s.pkt) {
		return nil
	}
	n := min(s.mss, len(s.pkt)-s.off)
	seg := s.pkt[s.off-s.hdrLen : s.off+n]
	copy(seg, s.hdr[:s.hdrLen])
	if s.v4 {
		binary.BigEndian.PutUint16(seg[2:], uint16(len(seg)))
		binary.BigEndian.PutUint16(seg[4:], s.id+uint16(s.i))
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:], ^checksum.Checksum(seg[:s.ipLen], 0))
	} else {
		binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)-header.IPv6MinimumSize))
	}
	tcp := seg[s.ipLen:]
	binary.BigEndian.PutUint32(tcp[4:], s.seq+uint32(s.off-s.hdrLen))
	if s.off+n < len(s.pkt) {
		tcp[13] &^= uint8(header.TCPFlagFin | header.TCPFlagPsh)
	}
	if s.i > 0 {
		tcp[13] &^= uint8(header.TCPFlagCwr)
	}
	tcp[16], tcp[17] = 0, 0
	sum := checksum.Checksum(tcp, checksum.Combine(s.pseudo, uint16(len(tcp))))
	binary.BigEndian.PutUint16(tcp[16:], ^sum)
	s.off += n
	s.i++
	return seg
}
