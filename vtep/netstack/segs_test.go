// SPDX-License-Identifier: AGPL-3.0-only

package netstack

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

// tcpOpts is the length of the options in the packets of tcpPacket.
const tcpOpts = 12

// tcpPacket returns a TCP packet with the payload and tcpOpts bytes of options.
// With gso, the checksum has only the pseudo-header, as TCP gives a GSO packet
// to the link. Else the checksums are valid.
func tcpPacket(src, dst netip.Addr, sport uint16, seq, ack uint32, flags header.TCPFlags, payload []byte, gso bool) []byte {
	ipLen := header.IPv4MinimumSize
	if src.Is6() {
		ipLen = header.IPv6MinimumSize
	}
	tcpLen := header.TCPMinimumSize + tcpOpts
	b := make([]byte, ipLen+tcpLen+len(payload))
	srcA, dstA := tcpip.AddrFromSlice(src.AsSlice()), tcpip.AddrFromSlice(dst.AsSlice())
	if src.Is4() {
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			ID:          0xfffe,
			TTL:         64,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     srcA,
			DstAddr:     dstA,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
	} else {
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(tcpLen + len(payload)),
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcA,
			DstAddr:           dstA,
		})
	}
	tcp := header.TCP(b[ipLen:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    443,
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: uint8(tcpLen),
		Flags:      flags,
		WindowSize: 512,
	})
	opts := tcp[header.TCPMinimumSize:tcpLen]
	header.EncodeTSOption(1, 2, opts[header.EncodeNOP(opts)+header.EncodeNOP(opts[1:]):])
	copy(tcp.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcA, dstA, uint16(len(tcp)))
	if gso {
		tcp.SetChecksum(xsum)
	} else {
		tcp.SetChecksum(^tcp.CalculateChecksum(checksum.Combine(xsum, checksum.Checksum(payload, 0))))
	}
	return b
}

// pattern returns n bytes that differ at each offset.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7 / 3)
	}
	return b
}

// TestTCPSegs cuts GSO packets into packets of the MSS and checks each one.
func TestTCPSegs(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	v6a, v6b := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	const seq = 0xffff_f000 // The sequence numbers wrap.
	all := header.TCPFlagAck | header.TCPFlagPsh | header.TCPFlagFin | header.TCPFlagCwr
	cases := []struct {
		name     string
		src, dst netip.Addr
		payload  int
		mss      int
		flags    header.TCPFlags
		want     int // Packets.
	}{
		{name: "IPv4 last short", src: v4a, dst: v4b, payload: 4500, mss: 1000, flags: header.TCPFlagAck | header.TCPFlagPsh, want: 5},
		{name: "IPv6 last short", src: v6a, dst: v6b, payload: 4500, mss: 1000, flags: header.TCPFlagAck | header.TCPFlagPsh, want: 5},
		{name: "IPv4 full", src: v4a, dst: v4b, payload: 3 * 1208, mss: 1208, flags: header.TCPFlagAck, want: 3},
		{name: "IPv6 most", src: v6a, dst: v6b, payload: 1<<16 - 1 - header.IPv6MinimumSize - 32, mss: 1208, flags: header.TCPFlagAck, want: 55},
		{name: "IPv4 most", src: v4a, dst: v4b, payload: 1<<16 - 1 - header.IPv4MinimumSize - 32, mss: 1360, flags: header.TCPFlagAck, want: 49},
		{name: "odd MSS", src: v6a, dst: v6b, payload: 1001, mss: 333, flags: all, want: 4},
		{name: "MSS below header", src: v4a, dst: v4b, payload: 100, mss: 7, flags: all, want: 15},
		{name: "FIN PSH CWR", src: v4a, dst: v4b, payload: 2500, mss: 1000, flags: all, want: 3},
		{name: "one packet", src: v6a, dst: v6b, payload: 999, mss: 1000, flags: all, want: 1},
		{name: "no payload", src: v4a, dst: v4b, mss: 1000, flags: header.TCPFlagAck | header.TCPFlagFin, want: 1},
		{name: "MSS 0", src: v6a, dst: v6b, payload: 3000, flags: header.TCPFlagAck, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := pattern(tc.payload)
			pkt := tcpPacket(tc.src, tc.dst, 1000, seq, 7, tc.flags, payload, true)
			orig := bytes.Clone(pkt)
			ipLen := header.IPv4MinimumSize
			if tc.src.Is6() {
				ipLen = header.IPv6MinimumSize
			}
			hdrLen := ipLen + header.TCPMinimumSize + tcpOpts
			mss := tc.mss
			if mss == 0 {
				mss = tc.payload
			}

			var s tcpSegs
			require.True(t, s.init(pkt, ipLen, tc.mss))
			var got [][]byte
			for seg := s.next(); seg != nil; seg = s.next() {
				// The next packet writes over this one.
				got = append(got, bytes.Clone(seg))
			}
			require.Len(t, got, tc.want)

			srcA, dstA := tcpip.AddrFromSlice(tc.src.AsSlice()), tcpip.AddrFromSlice(tc.dst.AsSlice())
			var joined []byte
			for i, seg := range got {
				last := i == len(got)-1
				msg := fmt.Sprintf("packet %d", i)
				if tc.src.Is4() {
					ip := header.IPv4(seg)
					assert.True(t, ip.IsValid(len(seg)), msg)
					assert.True(t, ip.IsChecksumValid(), msg)
					assert.Equal(t, uint16(0xfffe+i), ip.ID(), msg)
				} else {
					assert.Equal(t, len(seg)-ipLen, int(header.IPv6(seg).PayloadLength()), msg)
				}
				tcp := header.TCP(seg[ipLen:])
				assert.Equal(t, uint32(seq+i*mss), tcp.SequenceNumber(), msg)
				want := tc.flags
				if !last {
					want &^= header.TCPFlagFin | header.TCPFlagPsh
				}
				if i > 0 {
					want &^= header.TCPFlagCwr
				}
				assert.Equal(t, want, tcp.Flags(), msg)
				p := tcp.Payload()
				if !last {
					assert.Len(t, p, mss, msg)
				}
				assert.True(t, tcp.IsChecksumValid(srcA, dstA, checksum.Checksum(p, 0), uint16(len(p))), msg)
				// The other bytes of the headers do not change.
				h, o := bytes.Clone(seg[:hdrLen]), bytes.Clone(orig[:hdrLen])
				for _, b := range [][]byte{h, o} {
					if tc.src.Is4() {
						clear(b[2:6])
						clear(b[10:12])
					} else {
						clear(b[4:6])
					}
					clear(b[ipLen+4 : ipLen+8])
					b[ipLen+13] = 0
					clear(b[ipLen+16 : ipLen+18])
				}
				assert.Equal(t, o, h, msg)
				joined = append(joined, p...)
			}
			assert.True(t, bytes.Equal(payload, joined), "the payloads do not make the original payload")
		})
	}
}

// TestTCPSegsBad checks that init refuses packets that it cannot cut.
func TestTCPSegsBad(t *testing.T) {
	v4 := tcpPacket(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1, 0, 0, header.TCPFlagAck, pattern(100), true)
	v6 := tcpPacket(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 1, 0, 0, header.TCPFlagAck, pattern(100), true)
	edit := func(p []byte, f func([]byte)) []byte {
		p = bytes.Clone(p)
		f(p)
		return p
	}
	cases := []struct {
		name  string
		pkt   []byte
		ipLen int
	}{
		{name: "IPv4 header length", pkt: v4, ipLen: header.IPv4MinimumSize + 4},
		{name: "IPv4 UDP", pkt: edit(v4, func(p []byte) { p[9] = uint8(header.UDPProtocolNumber) }), ipLen: header.IPv4MinimumSize},
		{name: "IPv6 short header", pkt: v6, ipLen: header.IPv4MinimumSize},
		{name: "version", pkt: edit(v4, func(p []byte) { p[0] = 0x55 }), ipLen: header.IPv4MinimumSize},
		{name: "TCP data offset", pkt: edit(v6, func(p []byte) { p[header.IPv6MinimumSize+12] = 4 << 4 }), ipLen: header.IPv6MinimumSize},
		{name: "TCP header past end", pkt: v4[:header.IPv4MinimumSize+header.TCPMinimumSize+4], ipLen: header.IPv4MinimumSize},
		{name: "short", pkt: v6[:header.IPv6MinimumSize+10], ipLen: header.IPv6MinimumSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s tcpSegs
			assert.False(t, s.init(tc.pkt, tc.ipLen, 50))
		})
	}
}

// groRecorder keeps a copy of each packet that GRO gives.
type groRecorder struct{ pkts [][]byte }

func (r *groRecorder) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	v := pkt.ToView()
	r.pkts = append(r.pkts, bytes.Clone(v.AsSlice()))
	v.Release()
}

func (*groRecorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestSplitJoin cuts a GSO packet and gives the packets to gVisor GRO, which
// checks their checksums. GRO must make one segment with the payload and the
// flags of the original.
func TestSplitJoin(t *testing.T) {
	for _, pair := range [][2]netip.Addr{
		{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
		{netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")},
	} {
		t.Run(pair[0].String(), func(t *testing.T) {
			const segs, mss = 20, 1000
			ipLen, proto := header.IPv4MinimumSize, header.IPv4ProtocolNumber
			if pair[0].Is6() {
				ipLen, proto = header.IPv6MinimumSize, header.IPv6ProtocolNumber
			}
			flags := header.TCPFlagAck | header.TCPFlagPsh
			payload := pattern(segs * mss)
			pkt := tcpPacket(pair[0], pair[1], 1000, 5, 7, flags, payload, true)
			var s tcpSegs
			require.True(t, s.init(pkt, ipLen, mss))

			r := &groRecorder{}
			g := &gro.GRO{Dispatcher: r}
			g.Init(true)
			for seg := s.next(); seg != nil; seg = s.next() {
				pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(seg)})
				pkb.NetworkProtocolNumber = proto
				g.Enqueue(pkb)
				pkb.DecRef()
			}
			g.Flush()

			require.Len(t, r.pkts, 1)
			tcp := header.TCP(r.pkts[0][ipLen:])
			assert.Equal(t, uint32(5), tcp.SequenceNumber())
			assert.Equal(t, flags, tcp.Flags())
			assert.True(t, bytes.Equal(payload, tcp.Payload()))
		})
	}
}

// BenchmarkTCPSegs cuts a GSO packet of 64 KiB into packets of the MSS of an
// inner MTU of 1280 and 1412.
func BenchmarkTCPSegs(b *testing.B) {
	for _, bc := range []struct {
		v6  bool
		mss int
	}{{false, 1228}, {true, 1208}, {true, 1340}} {
		b.Run(fmt.Sprintf("v6=%t/mss=%d", bc.v6, bc.mss), func(b *testing.B) {
			src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
			ipLen := header.IPv4MinimumSize
			if bc.v6 {
				src, dst = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
				ipLen = header.IPv6MinimumSize
			}
			pkt := tcpPacket(src, dst, 1, 0, 0, header.TCPFlagAck, pattern(1<<16-1-ipLen-32), true)
			hdr := bytes.Clone(pkt[:ipLen+header.TCPMinimumSize+tcpOpts])
			var s tcpSegs
			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()
			for b.Loop() {
				copy(pkt, hdr)
				s.init(pkt, ipLen, bc.mss)
				for seg := s.next(); seg != nil; seg = s.next() {
				}
			}
		})
	}
}
