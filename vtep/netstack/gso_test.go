// SPDX-License-Identifier: AGPL-3.0-only

package netstack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// recUnderlay keeps a copy of each frame that the datapath writes. When
// writeMax is set, a write takes at most writeMax frames.
type recUnderlay struct {
	frames   [][]byte
	writes   int
	writeMax int
}

func (*recUnderlay) ReadFrame([]byte) (int, error) { return 0, net.ErrClosed }

func (u *recUnderlay) WriteFrames(frames [][]byte) (int, error) {
	u.writes++
	n := len(frames)
	if u.writeMax > 0 {
		n = min(n, u.writeMax)
	}
	for _, f := range frames[:n] {
		u.frames = append(u.frames, bytes.Clone(f))
	}
	return n, nil
}

// newPacket returns a packet buffer of the IP packet p with ipLen bytes of IP
// headers. A non-zero mss gives it the GSO options of TCP.
func newPacket(p []byte, ipLen, mss int) *stack.PacketBuffer {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	pkb.NetworkHeader().Consume(ipLen)
	pkb.GSOOptions = gsoOptions(p, ipLen, mss)
	return pkb
}

// gsoOptions returns the GSO options of TCP for the IP packet p, or no GSO
// for an mss of 0.
func gsoOptions(p []byte, ipLen, mss int) stack.GSO {
	if mss == 0 {
		return stack.GSO{}
	}
	typ := stack.GSOTCPv4
	if p[0]>>4 == header.IPv6Version {
		typ = stack.GSOTCPv6
	}
	return stack.GSO{Type: typ, NeedsCsum: true, MSS: uint16(mss), L3HdrLen: uint16(ipLen)}
}

// stackPacket returns the TCP packet p as the stack makes it: pushed IP and TCP
// headers, and the payload in views that start at view bytes and grow 3 times.
func stackPacket(p []byte, ipLen, mss, view int) *stack.PacketBuffer {
	hdrLen := ipLen + int(p[ipLen+12]>>4)*4
	var data buffer.Buffer
	for n, rest := view, p[hdrLen:]; len(rest) > 0; n = 3*n + 1 {
		k := min(n, len(rest))
		data.Append(buffer.NewViewWithData(rest[:k]))
		rest = rest[k:]
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: hdrLen, Payload: data})
	copy(pkb.TransportHeader().Push(hdrLen-ipLen), p[ipLen:hdrLen])
	copy(pkb.NetworkHeader().Push(ipLen), p[:ipLen])
	pkb.GSOOptions = gsoOptions(p, ipLen, mss)
	return pkb
}

// writePackets writes the packets of pkts to ep and empties pkts.
func writePackets(t testing.TB, ep *channel.Endpoint, pkts *stack.PacketBufferList) {
	t.Helper()
	defer pkts.Reset()
	if n, err := ep.WritePackets(*pkts); err != nil || n != pkts.Len() {
		t.Fatalf("wrote %d of %d packets: %v", n, pkts.Len(), err)
	}
}

// TestDatapathGSO writes packets to the endpoint and runs the send path once.
// A packet with GSO must become packets of the MSS, in order and with valid
// checksums.
func TestDatapathGSO(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	v6a, v6b := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	type pkt struct {
		v6      bool
		payload int
		mss     int // Zero writes the packet with no GSO.
		badIP   bool
	}
	cases := []struct {
		name     string
		pkts     []pkt
		writeMax int
		want     []int // The payload length of each frame.
	}{
		{name: "IPv4", pkts: []pkt{{payload: 4500, mss: 1000}}, want: []int{1000, 1000, 1000, 1000, 500}},
		{name: "IPv6", pkts: []pkt{{v6: true, payload: 2000, mss: 1000}}, want: []int{1000, 1000}},
		{name: "no GSO", pkts: []pkt{{payload: 1200}}, want: []int{1200}},
		{name: "GSO and no GSO in order", pkts: []pkt{{payload: 1500, mss: 1000}, {v6: true, payload: 10}}, want: []int{1000, 500, 10}},
		{name: "bad IP header", pkts: []pkt{{v6: true, payload: 3000, mss: 1000, badIP: true}, {payload: 10}}, want: []int{10}},
		{name: "short writes", pkts: []pkt{{payload: 10_000, mss: 1000}}, writeMax: 3, want: repeat(1000, 10)},
		// More frames than one batch.
		{name: "many", pkts: []pkt{{v6: true, payload: 60_000, mss: 400}}, want: repeat(400, 150)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := channel.New(16, 1500, "")
			u := &recUnderlay{writeMax: tc.writeMax}
			d, err := New(Config{Engine: fakeEngine{}, Endpoint: ep, Underlay: u})
			require.NoError(t, err)
			defer d.Close()
			for _, p := range tc.pkts {
				src, dst, ipLen := v4a, v4b, header.IPv4MinimumSize
				if p.v6 {
					src, dst, ipLen = v6a, v6b, header.IPv6MinimumSize
				}
				b := tcpPacket(src, dst, 1000, 0, 7, header.TCPFlagAck, pattern(p.payload), p.mss > 0)
				if p.badIP {
					ipLen = header.IPv4MinimumSize
				}
				var pkts stack.PacketBufferList
				pkts.PushBack(newPacket(b, ipLen, p.mss))
				writePackets(t, ep, &pkts)
			}
			require.NoError(t, d.sendQueued())

			got := make([]int, len(u.frames))
			for i, f := range u.frames {
				ipLen := header.IPv4MinimumSize
				src, dst := tcpip.AddrFromSlice(f[12:16]), tcpip.AddrFromSlice(f[16:20])
				if f[0]>>4 == header.IPv6Version {
					ipLen = header.IPv6MinimumSize
					src, dst = tcpip.AddrFromSlice(f[8:24]), tcpip.AddrFromSlice(f[24:40])
				} else {
					assert.True(t, header.IPv4(f).IsChecksumValid(), "frame %d", i)
				}
				th := header.TCP(f[ipLen:])
				p := th.Payload()
				got[i] = len(p)
				assert.True(t, th.IsChecksumValid(src, dst, checksum.Checksum(p, 0), uint16(len(p))), "frame %d", i)
			}
			assert.Equal(t, tc.want, got)
			if tc.writeMax > 0 {
				assert.Greater(t, u.writes, 1)
			}
		})
	}
}

// repeat returns n copies of v.
func repeat(v, n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = v
	}
	return s
}

// newTCPStack makes a TCP stack on ep with the address a.
func newTCPStack(t *testing.T, ep *channel.Endpoint, a netip.Addr) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(s.Close)
	require.Nil(t, s.CreateNIC(1, ep))
	proto := ipv4.ProtocolNumber
	if a.Is6() {
		proto = ipv6.ProtocolNumber
	}
	pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}
	require.Nil(t, s.AddProtocolAddress(1, pa, stack.AddressProperties{}))
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	return s
}

// TestDatapathTCPGSO sends TCP from a stack with GSO through two datapaths to
// another stack. The data must arrive whole, and no frame can be larger than
// the MTU. The datapaths have no pipe, or a pipe whose seal workers cut the
// TCP packets, also when the engine refuses some of them.
func TestDatapathTCPGSO(t *testing.T) {
	third := 0
	cases := []struct {
		name    string
		workers int
		segs    func([]byte, int, int, int) bool
	}{
		{name: "no pipe"},
		{name: "pipe", workers: 2},
		{name: "pipe, each third refused", workers: 2, segs: func([]byte, int, int, int) bool { third++; return third%3 != 0 }},
	}
	for _, tc := range cases {
		for _, pair := range [][2]netip.Addr{
			{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
			{netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")},
		} {
			t.Run(tc.name+"/"+pair[0].String(), func(t *testing.T) {
				epA, epB := channel.New(256, testMTU, ""), channel.New(256, testMTU, "")
				epA.SupportedGSOKind = stack.HostGSOSupported
				sA, sB := newTCPStack(t, epA, pair[0]), newTCPStack(t, epB, pair[1])
				uA, uB := newFakeUnderlay(), newFakeUnderlay()
				var frames, maxLen atomic.Int64
				// Each underlay sends its frames to the other.
				cross := func(from, to *fakeUnderlay, count bool) {
					for {
						select {
						case f := <-from.out:
							if count {
								frames.Add(1)
								if n := int64(len(f)); n > maxLen.Load() {
									maxLen.Store(n)
								}
							}
							select {
							case to.in <- f:
							case <-to.closed:
								return
							}
						case <-from.closed:
							return
						}
					}
				}
				go cross(uA, uB, true)
				go cross(uB, uA, false)
				overhead := 0
				if tc.workers == noPipe {
					defer startDatapath(t, fakeEngine{}, epA, uA)()
					defer startDatapath(t, fakeEngine{}, epB, uB)()
				} else {
					overhead = seqLen
					defer startPipeDatapath(t, &seqEngine{segs: tc.segs}, epA, uA, tc.workers)()
					defer startPipeDatapath(t, &seqEngine{}, epB, uB, tc.workers)()
				}

				proto := ipv4.ProtocolNumber
				if pair[0].Is6() {
					proto = ipv6.ProtocolNumber
				}
				dst := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(pair[1].AsSlice()), Port: 80}
				ln, err := gonet.ListenTCP(sB, dst, proto)
				require.NoError(t, err)
				defer ln.Close()
				data := pattern(256 << 10)
				got := make(chan []byte, 1)
				go func() {
					c, err := ln.Accept()
					if err != nil {
						got <- nil
						return
					}
					defer c.Close()
					b, _ := io.ReadAll(c)
					got <- b
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				c, err := gonet.DialContextTCP(ctx, sA, dst, proto)
				require.NoError(t, err)
				_, err = c.Write(data)
				require.NoError(t, err)
				require.NoError(t, c.Close())
				select {
				case b := <-got:
					assert.True(t, bytes.Equal(data, b), "got %d of %d bytes", len(b), len(data))
				case <-ctx.Done():
					t.Fatal("the data did not arrive")
				}
				assert.LessOrEqual(t, maxLen.Load(), int64(testMTU+overhead))
				// The stack sends fewer packets than the datapath sends frames.
				assert.Less(t, sA.NICInfo()[1].Stats.Tx.Packets.Value(), uint64(frames.Load()))
			})
		}
	}
}

// startPipeDatapath runs a datapath on ep with a send pipe of workers seal
// workers. The returned function stops it.
func startPipeDatapath(t *testing.T, eng Sealer, ep *channel.Endpoint, u *fakeUnderlay, workers int) func() {
	t.Helper()
	d, err := New(Config{Engine: eng, Endpoint: ep, Underlay: u, FlushInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	d.pipe = newTxPipe(d, eng, workers)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	return func() {
		cancel()
		u.Close()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("Run did not return")
		}
	}
}

// nopUnderlay drops the frames that it gets.
type nopUnderlay struct{}

func (nopUnderlay) ReadFrame([]byte) (int, error)            { return 0, net.ErrClosed }
func (nopUnderlay) WriteFrames(frames [][]byte) (int, error) { return len(frames), nil }

// benchPackets returns 64 KiB of IPv6 TCP payload as one GSO packet or as
// packets of the MSS.
func benchPackets(gso bool) (pkts [][]byte, mss, size int) {
	const segs = 54
	mss = 1208
	src, dst := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	payload := pattern(segs * mss)
	if gso {
		return [][]byte{tcpPacket(src, dst, 1, 0, 0, header.TCPFlagAck, payload, true)}, mss, len(payload)
	}
	for i := range segs {
		pkts = append(pkts, tcpPacket(src, dst, 1, uint32(i*mss), 0, header.TCPFlagAck, payload[i*mss:(i+1)*mss], false))
	}
	return pkts, 0, len(payload)
}

// TestPktBufTake copies packets with consumed headers, as the tests make
// them, and with pushed headers, as the stack makes them. The copy must equal
// ToView, and the buffer must not grow for a packet that fits.
func TestPktBufTake(t *testing.T) {
	v4a, v4b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	v6a, v6b := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	cases := []struct {
		name string
		pkt  *stack.PacketBuffer
	}{
		{"v4 consumed header", newPacket(tcpPacket(v4a, v4b, 1, 0, 0, header.TCPFlagAck, pattern(100), false), header.IPv4MinimumSize, 0)},
		{"v6 GSO consumed header", newPacket(tcpPacket(v6a, v6b, 1, 0, 0, header.TCPFlagAck, pattern(60000), true), header.IPv6MinimumSize, 1208)},
		{"v6 pushed headers", stackPacket(tcpPacket(v6a, v6b, 1, 0, 0, header.TCPFlagAck, pattern(3000), true), header.IPv6MinimumSize, 0, 1)},
	}
	p := pktBuf{b: make([]byte, 0, 1<<16)}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.pkt.DecRef()
			want := tc.pkt.ToView()
			defer want.Release()
			got := p.take(tc.pkt)
			assert.Equal(t, want.AsSlice(), got)
			assert.Equal(t, 1<<16, cap(got))
		})
	}
}

// BenchmarkSendQueued writes the packets to the endpoint and sends them.
func BenchmarkSendQueued(b *testing.B) {
	for _, gso := range []bool{true, false} {
		b.Run(fmt.Sprintf("gso=%t", gso), func(b *testing.B) {
			pkts, mss, size := benchPackets(gso)
			ep := channel.New(256, 1500, "")
			d, err := New(Config{Engine: fakeEngine{}, Endpoint: ep, Underlay: nopUnderlay{}})
			require.NoError(b, err)
			defer d.Close()
			var list stack.PacketBufferList
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				for _, p := range pkts {
					list.PushBack(newPacket(p, header.IPv6MinimumSize, mss))
				}
				writePackets(b, ep, &list)
				if err := d.sendQueued(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAddPacket cuts and sends the packets with no endpoint. It measures
// only the work of the datapath.
func BenchmarkAddPacket(b *testing.B) {
	for _, gso := range []bool{true, false} {
		b.Run(fmt.Sprintf("gso=%t", gso), func(b *testing.B) {
			pkts, mss, size := benchPackets(gso)
			d, err := New(Config{Engine: fakeEngine{}, Endpoint: channel.New(1, 1500, ""), Underlay: nopUnderlay{}})
			require.NoError(b, err)
			defer d.Close()
			opts := stack.GSO{}
			if gso {
				opts = stack.GSO{Type: stack.GSOTCPv6, NeedsCsum: true, MSS: uint16(mss), L3HdrLen: header.IPv6MinimumSize}
			}
			buf := make([]byte, 0, 1<<16)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				for _, p := range pkts {
					// The cut writes into the packet, so cut a copy.
					buf = append(buf[:0], p...)
					if err := d.addPacket(buf, opts, header.IPv6MinimumSize); err != nil {
						b.Fatal(err)
					}
				}
				if err := d.send(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
