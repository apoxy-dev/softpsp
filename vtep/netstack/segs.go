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
// does. It keeps the headers of the packet and makes the headers of each one.
type tcpSegs struct {
	hdr    [maxSegHdr]byte // The headers of the packet.
	ipLen  int
	hdrLen int
	size   int // The length of the packet: the headers and the payload.
	mss    int
	off    int // Offset of the next payload in the packet.
	i      int // Index of the next packet.
	seq    uint32
	id     uint16
	ipSum  uint16 // IPv4 header checksum without the length and the ID.
	pseudo uint16 // Pseudo-header checksum without the length.
	v4     bool
}

// init prepares to cut a packet of size bytes. hdr is the start of the packet:
// ipLen bytes of IPv4 or IPv6 headers and then a TCP header, or more. An mss
// of 0 gives one packet. It returns false when it cannot cut the packet.
func (s *tcpSegs) init(hdr []byte, ipLen, size, mss int) bool {
	if len(hdr) < ipLen+header.TCPMinimumSize {
		return false
	}
	switch hdr[0] >> 4 {
	case header.IPv4Version:
		if ipLen != int(hdr[0]&0xf)*4 || ipLen < header.IPv4MinimumSize || hdr[9] != uint8(header.TCPProtocolNumber) {
			return false
		}
		s.v4 = true
		s.id = binary.BigEndian.Uint16(hdr[4:])
		s.pseudo = checksum.Checksum(hdr[12:20], 0)
	case header.IPv6Version:
		if ipLen < header.IPv6MinimumSize {
			return false
		}
		s.v4 = false
		s.pseudo = checksum.Checksum(hdr[8:40], 0)
	default:
		return false
	}
	tcpLen := int(hdr[ipLen+12]>>4) * 4
	if tcpLen < header.TCPMinimumSize || ipLen+tcpLen > min(len(hdr), maxSegHdr) {
		return false
	}
	s.pseudo = checksum.Combine(s.pseudo, uint16(header.TCPProtocolNumber))
	s.ipLen, s.hdrLen, s.size = ipLen, ipLen+tcpLen, size
	copy(s.hdr[:], hdr[:s.hdrLen])
	if s.v4 {
		// header sets the length, the ID and the checksum of each packet.
		clear(s.hdr[2:6])
		s.hdr[10], s.hdr[11] = 0, 0
		s.ipSum = checksum.Checksum(s.hdr[:ipLen], 0)
	}
	s.seq = binary.BigEndian.Uint32(hdr[ipLen+4:])
	s.mss = mss
	if mss <= 0 {
		s.mss = size - s.hdrLen
	}
	s.off, s.i = s.hdrLen, 0
	return true
}

// count returns the number of packets of the cut.
func (s *tcpSegs) count() int {
	payload := s.size - s.hdrLen
	if payload <= s.mss {
		return 1
	}
	return (payload + s.mss - 1) / s.mss
}

// seek makes packet i the next packet.
func (s *tcpSegs) seek(i int) { s.i, s.off = i, s.hdrLen+i*s.mss }

// length returns the payload length of the next packet.
func (s *tcpSegs) length() int { return min(s.mss, s.size-s.off) }

// header writes the headers of the next packet to seg, before its payload, and
// moves on. The TCP checksum has only the pseudo-header sum: see tcpChecksum.
func (s *tcpSegs) header(seg []byte) {
	n := len(seg) - s.hdrLen
	copy(seg, s.hdr[:s.hdrLen])
	if s.v4 {
		id := s.id + uint16(s.i)
		binary.BigEndian.PutUint16(seg[2:], uint16(len(seg)))
		binary.BigEndian.PutUint16(seg[4:], id)
		sum := checksum.Combine(checksum.Combine(s.ipSum, uint16(len(seg))), id)
		binary.BigEndian.PutUint16(seg[10:], ^sum)
	} else {
		binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)-header.IPv6MinimumSize))
	}
	tcp := seg[s.ipLen:]
	binary.BigEndian.PutUint32(tcp[4:], s.seq+uint32(s.off-s.hdrLen))
	if s.off+n < s.size {
		tcp[13] &^= uint8(header.TCPFlagFin | header.TCPFlagPsh)
	}
	if s.i > 0 {
		tcp[13] &^= uint8(header.TCPFlagCwr)
	}
	binary.BigEndian.PutUint16(tcp[16:], checksum.Combine(s.pseudo, uint16(len(tcp))))
	s.off += n
	s.i++
}

// next returns the next packet in pkt, the packet of init, or nil at the end.
// Its headers go over the previous packet: use each packet before the next.
func (s *tcpSegs) next(pkt []byte) []byte {
	if s.i > 0 && s.off >= s.size {
		return nil
	}
	seg := pkt[s.off-s.hdrLen : s.off+s.length()]
	s.header(seg)
	return seg
}

// tcpChecksum completes the TCP checksum of pkt, a packet of header with ipLen
// bytes of IP headers.
func tcpChecksum(pkt []byte, ipLen int) {
	tcp := pkt[ipLen:]
	sum := binary.BigEndian.Uint16(tcp[16:])
	tcp[16], tcp[17] = 0, 0
	binary.BigEndian.PutUint16(tcp[16:], ^checksum.Checksum(tcp, sum))
}
