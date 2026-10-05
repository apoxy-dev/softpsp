// SPDX-License-Identifier: Apache-2.0

package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/psp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// seqEngine is a Sealer whose frame is the number of Prepare and then the
// inner packet, so that the frames show the send order.
type seqEngine struct {
	seq     uint64            // Prepare runs on the send pump only.
	drop    func([]byte) bool // Prepare drops these packets.
	fail    func(uint64) bool // Seal drops the frames with these numbers.
	shuffle bool              // Seal waits a random time.
	hold    chan struct{}     // When set, Seal waits until it closes.
	holding atomic.Int32      // Seals that wait for hold.
	keep    [][]byte          // ToPhy returns these one by one.
}

const seqLen = 8

func (e *seqEngine) Overhead() int { return seqLen }

func (e *seqEngine) Prepare(virt []byte, f *TxFrame) bool {
	if e.drop != nil && e.drop(virt) {
		return false
	}
	f.Seq = e.seq
	e.seq++
	return true
}

func (e *seqEngine) Seal(f *TxFrame, virt, phy []byte) int {
	if e.hold != nil {
		e.holding.Add(1)
		<-e.hold
	}
	if e.shuffle {
		time.Sleep(time.Duration(rand.IntN(200)) * time.Microsecond)
	}
	if e.fail != nil && e.fail(f.Seq) {
		return 0
	}
	binary.BigEndian.PutUint64(phy, f.Seq)
	return seqLen + copy(phy[seqLen:], virt)
}

func (e *seqEngine) VirtToPhy(virt, phy []byte) (int, bool) {
	var f TxFrame
	if !e.Prepare(virt, &f) {
		return 0, false
	}
	return e.Seal(&f, virt, phy), false
}

func (e *seqEngine) PhyToVirt(phy, virt []byte) int { return copy(virt, phy) }

// ToPhy gives the frames of keep after the first Prepare, so that the pump
// sends them after the frames of the first packet.
func (e *seqEngine) ToPhy(phy []byte) int {
	if e.seq == 0 || len(e.keep) == 0 {
		return 0
	}
	n := copy(phy, e.keep[0])
	e.keep = e.keep[1:]
	return n
}

// pspEngine is a Sealer on one real transmit SA. Its frame is the PSP packet,
// and open gives the inner packet of a frame.
type pspEngine struct {
	tx *engine.TxSA
	rx *engine.RxQueue
}

func newPSPEngine(t testing.TB) *pspEngine {
	t.Helper()
	tab, err := engine.NewRxTable(engine.RxConfig{RowBits: 4})
	require.NoError(t, err)
	sa := engine.RxSA{
		Master:  bytes.Repeat([]byte{7}, psp.MasterKeyLen),
		Version: psp.AESGCM128,
		VNI:     0x123,
		MTU:     testMTU,
		Sources: func(netip.Addr) bool { return true },
	}
	spi, key, err := tab.Add(sa)
	require.NoError(t, err)
	tx, err := engine.NewTxSA(spi, key, sa.VNI, sa.MTU)
	require.NoError(t, err)
	return &pspEngine{tx: tx, rx: tab.Queue(0)}
}

func (e *pspEngine) Overhead() int { return psp.Overhead }

func (e *pspEngine) Prepare(_ []byte, f *TxFrame) bool {
	seq, err := e.tx.Reserve()
	f.SA, f.Seq = e.tx, seq
	return err == nil
}

func (e *pspEngine) Seal(f *TxFrame, virt, phy []byte) int {
	n, _ := f.SA.SealSeq(f.Seq, phy, virt)
	return n
}

func (e *pspEngine) VirtToPhy(virt, phy []byte) (int, bool) {
	var f TxFrame
	if !e.Prepare(virt, &f) {
		return 0, false
	}
	return e.Seal(&f, virt, phy), false
}

func (e *pspEngine) PhyToVirt([]byte, []byte) int { return 0 }
func (e *pspEngine) ToPhy([]byte) int             { return 0 }

// open returns the inner packet of frame. The receive SA must accept the
// frame, so a frame out of the replay window fails the test.
func (e *pspEngine) open(t testing.TB, frame []byte) []byte {
	t.Helper()
	inner, _, err := e.rx.Receive(frame)
	require.NoError(t, err)
	return inner
}

// syncUnderlay keeps a copy of each frame. With block, a write waits until
// Close and returns net.ErrClosed.
type syncUnderlay struct {
	mu      sync.Mutex
	frames  [][]byte
	block   bool
	writing atomic.Int32 // Writes that wait for Close.
	closed  chan struct{}
	once    sync.Once
}

func newSyncUnderlay() *syncUnderlay { return &syncUnderlay{closed: make(chan struct{})} }

func (u *syncUnderlay) ReadFrame([]byte) (int, error) {
	<-u.closed
	return 0, net.ErrClosed
}

func (u *syncUnderlay) WriteFrames(frames [][]byte) (int, error) {
	if u.block {
		u.writing.Add(1)
		<-u.closed
		return 0, net.ErrClosed
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, f := range frames {
		u.frames = append(u.frames, bytes.Clone(f))
	}
	return len(frames), nil
}

func (u *syncUnderlay) Close() { u.once.Do(func() { close(u.closed) }) }

func (u *syncUnderlay) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.frames)
}

// noPipe is the workers of newPipeDatapath for a datapath with no send pipe.
const noPipe = 0

// newPipeDatapath returns a datapath on eng and u with a send pipe of workers
// seal workers, or with no pipe for noPipe.
func newPipeDatapath(t testing.TB, eng Sealer, u Underlay, workers int) *Datapath {
	t.Helper()
	d, err := New(Config{Engine: eng, Endpoint: channel.New(1024, testMTU, ""), Underlay: u, FlushInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Close() })
	d.pipe = nil
	if workers > 0 {
		d.pipe = newTxPipe(d, eng, workers)
	}
	return d
}

// run runs d until the returned function is called, which closes d and u and
// waits for Run to return with no error.
func run(t *testing.T, d *Datapath, u *syncUnderlay) func() {
	t.Helper()
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
			t.Fatal("Run did not return")
		}
	}
}

// testPacket is one packet that a test writes to the endpoint: a TCP packet,
// or an IPv4 UDP packet.
type testPacket struct {
	v6      bool
	udp     bool
	payload int
	mss     int // Zero writes the packet with no GSO.
}

func (p testPacket) addrs() (src, dst netip.Addr) {
	if p.v6 {
		return netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	}
	return netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
}

// build returns packet i of a test and the length of its IP headers. The
// source port is 1000+i.
func (p testPacket) build(t testing.TB, i int) ([]byte, int) {
	src, dst := p.addrs()
	if p.udp {
		srcA, dstA := tcpip.AddrFromSlice(src.AsSlice()), tcpip.AddrFromSlice(dst.AsSlice())
		return buildUDPv4(t, srcA, dstA, uint16(1000+i), 9999, pattern(p.payload)), header.IPv4MinimumSize
	}
	ipLen := header.IPv4MinimumSize
	if p.v6 {
		ipLen = header.IPv6MinimumSize
	}
	return tcpPacket(src, dst, uint16(1000+i), uint32(i)<<16, 7, header.TCPFlagAck, pattern(p.payload), p.mss > 0), ipLen
}

// writeTestPackets writes pkts to ep, one write for each packet.
func writeTestPackets(t testing.TB, ep *channel.Endpoint, pkts []testPacket) {
	t.Helper()
	for i, p := range pkts {
		b, ipLen := p.build(t, i)
		var list stack.PacketBufferList
		list.PushBack(newPacket(b, ipLen, p.mss))
		writePackets(t, ep, &list)
	}
}

// wantPackets returns the inner packets that a datapath must send for pkts, in
// send order. A packet with an MSS gives the whole packets of wantSeg.
func wantPackets(t testing.TB, pkts []testPacket) [][]byte {
	var want [][]byte
	for i, p := range pkts {
		if p.mss == 0 {
			b, _ := p.build(t, i)
			want = append(want, b)
			continue
		}
		src, dst := p.addrs()
		payload := pattern(p.payload)
		for n, off := 0, 0; off < len(payload); n, off = n+1, off+p.mss {
			seg := payload[off:min(off+p.mss, len(payload))]
			want = append(want, wantSeg(src, dst, uint16(1000+i), uint32(i)<<16+uint32(off), 7, header.TCPFlagAck, seg, n))
		}
	}
	return want
}

// tcpSumValid reports whether the TCP checksum of the IP packet p is valid.
func tcpSumValid(p []byte) bool {
	ipLen := header.IPv4MinimumSize
	src, dst := tcpip.AddrFromSlice(p[12:16]), tcpip.AddrFromSlice(p[16:20])
	if p[0]>>4 == header.IPv6Version {
		ipLen = header.IPv6MinimumSize
		src, dst = tcpip.AddrFromSlice(p[8:24]), tcpip.AddrFromSlice(p[24:40])
	}
	th := header.TCP(p[ipLen:])
	data := th.Payload()
	return th.IsChecksumValid(src, dst, checksum.Checksum(data, 0), uint16(len(data)))
}

func TestSealWorkers(t *testing.T) {
	for procs, want := range map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 6: 1, 7: 1, 8: 2, 12: 3, 16: 4, 64: 4} {
		assert.Equal(t, want, sealWorkers(procs), "procs %d", procs)
	}
}

// TestNewPipe checks that New makes a pipe only for a Sealer.
func TestNewPipe(t *testing.T) {
	want := sealWorkers(runtime.GOMAXPROCS(0))
	for _, tc := range []struct {
		name string
		eng  Sealer
		pipe bool
	}{
		{"sealer", &seqEngine{}, want > 0},
		{"plain engine", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Engine: fakeEngine{}, Endpoint: channel.New(1, testMTU, ""), Underlay: newSyncUnderlay()}
			if tc.eng != nil {
				cfg.Engine = tc.eng
			}
			d, err := New(cfg)
			require.NoError(t, err)
			defer d.Close()
			assert.Equal(t, tc.pipe, d.pipe != nil)
			if d.pipe != nil {
				assert.Equal(t, want, d.pipe.workers)
			}
		})
	}
}

// TestTxPipe sends packets through a datapath with a send pipe. The frames
// must equal the frames of a datapath with no pipe: the same frames, in send
// order, also when the seal workers finish the sets in another order, when
// Prepare or Seal drops frames, and when the engine has frames of its own.
func TestTxPipe(t *testing.T) {
	cases := []struct {
		name string
		pkts []testPacket
		drop func([]byte) bool
		fail func(uint64) bool
		keep int
	}{
		{name: "GSO and plain", pkts: []testPacket{{payload: 4500, mss: 1000}, {v6: true, payload: 10}, {payload: 1200}, {v6: true, payload: 3000, mss: 1000}}},
		{name: "many sets", pkts: []testPacket{{payload: 60_000, mss: 400}, {v6: true, payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}}},
		{name: "Prepare drops", pkts: []testPacket{{payload: 60_000, mss: 400}, {payload: 50}}, drop: func(v []byte) bool { return v[len(v)-1]%5 == 0 }},
		{name: "Seal drops", pkts: []testPacket{{payload: 60_000, mss: 400}, {payload: 50}}, fail: func(seq uint64) bool { return seq%7 == 3 }},
		{name: "engine frames", pkts: []testPacket{{payload: 4000, mss: 1000}}, keep: 3},
	}
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 2, 4} {
			t.Run(fmt.Sprintf("%s/workers=%d", tc.name, workers), func(t *testing.T) {
				engine := func() *seqEngine {
					e := &seqEngine{drop: tc.drop, fail: tc.fail, shuffle: workers > 0}
					for i := range tc.keep {
						e.keep = append(e.keep, pattern(100+i))
					}
					return e
				}
				// The frames of the pump with no pipe are the frames to expect.
				wantU := newSyncUnderlay()
				wantD := newPipeDatapath(t, engine(), wantU, noPipe)
				writeTestPackets(t, wantD.ep, tc.pkts)
				require.NoError(t, wantD.sendQueued())
				want := wantU.frames
				require.NotEmpty(t, want)

				u := newSyncUnderlay()
				d := newPipeDatapath(t, engine(), u, workers)
				stop := run(t, d, u)
				writeTestPackets(t, d.ep, tc.pkts)
				require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
				stop()
				assert.Equal(t, len(want), u.count())
				for i := range min(len(want), u.count()) {
					if !assert.True(t, bytes.Equal(want[i], u.frames[i]), "frame %d", i) {
						break
					}
				}
			})
		}
	}
}

// TestTxPipeBytes seals packets with a real SA, with and without a send pipe,
// and opens the frames. Each inner packet must equal a packet that tcpPacket
// makes whole, in send order.
func TestTxPipeBytes(t *testing.T) {
	cases := []struct {
		name string
		pkts []testPacket
	}{
		{name: "IPv4 last short", pkts: []testPacket{{payload: 4500, mss: 1000}}},
		{name: "IPv6 last short", pkts: []testPacket{{v6: true, payload: 4500, mss: 1000}}},
		{name: "IPv4 odd lengths", pkts: []testPacket{{payload: 2501, mss: 999}}},
		{name: "IPv6 odd lengths", pkts: []testPacket{{v6: true, payload: 1001, mss: 333}}},
		{name: "IPv4 full", pkts: []testPacket{{payload: 3 * 1208, mss: 1208}}},
		{name: "GSO not cut", pkts: []testPacket{{payload: 999, mss: 1000}, {v6: true, payload: 1000, mss: 1000}}},
		{name: "no GSO", pkts: []testPacket{{payload: 1200}, {v6: true, payload: 1201}}},
		{name: "UDP", pkts: []testPacket{{udp: true, payload: 1200}, {udp: true, payload: 33}}},
		{name: "many sets", pkts: []testPacket{{payload: 60_000, mss: 400}, {udp: true, payload: 100}, {v6: true, payload: 60_001, mss: 401}, {payload: 70}, {v6: true, payload: 30_000, mss: 1208}}},
	}
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 4} {
			t.Run(fmt.Sprintf("%s/workers=%d", tc.name, workers), func(t *testing.T) {
				want := wantPackets(t, tc.pkts)
				eng := newPSPEngine(t)
				u := newSyncUnderlay()
				d := newPipeDatapath(t, eng, u, workers)
				stop := run(t, d, u)
				writeTestPackets(t, d.ep, tc.pkts)
				require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
				stop()
				require.Equal(t, len(want), u.count())
				for i, f := range u.frames {
					if !assert.True(t, bytes.Equal(want[i], eng.open(t, f)), "packet %d", i) {
						break
					}
				}
			})
		}
	}
}

// TestTxPipePrepare checks the packets that Prepare gets. Prepare can keep a
// packet that it drops. Thus a packet with an incomplete TCP checksum must
// come after a packet of the same GSO packet that Prepare took.
func TestTxPipePrepare(t *testing.T) {
	sport := func(v []byte) uint16 {
		if v[0]>>4 == header.IPv6Version {
			return binary.BigEndian.Uint16(v[header.IPv6MinimumSize:])
		}
		return binary.BigEndian.Uint16(v[header.IPv4MinimumSize:])
	}
	pkts := []testPacket{{payload: 9000, mss: 1000}, {v6: true, payload: 9000, mss: 1000}, {payload: 500}, {v6: true, payload: 9500, mss: 1000}, {payload: 700, mss: 1000}}
	cases := []struct {
		name string
		drop func(v []byte, n int) bool // n is the number of Prepare calls before this one.
	}{
		{name: "no drops", drop: func([]byte, int) bool { return false }},
		{name: "one flow has no route", drop: func(v []byte, _ int) bool { return sport(v) == 1001 }},
		{name: "each fifth packet", drop: func(_ []byte, n int) bool { return n%5 == 2 }},
	}
	type call struct {
		sport       uint16
		whole, took bool
	}
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 4} {
			t.Run(fmt.Sprintf("%s/workers=%d", tc.name, workers), func(t *testing.T) {
				var calls []call
				eng := &seqEngine{drop: func(v []byte) bool {
					c := call{sport: sport(v), whole: tcpSumValid(v), took: !tc.drop(v, len(calls))}
					calls = append(calls, c)
					return !c.took
				}}
				u := newSyncUnderlay()
				d := newPipeDatapath(t, eng, u, workers)
				stop := run(t, d, u)
				writeTestPackets(t, d.ep, pkts)
				// The last packet has one Prepare call, and no test case drops it.
				require.Eventually(t, func() bool {
					u.mu.Lock()
					defer u.mu.Unlock()
					return len(u.frames) > 0 && sport(u.frames[len(u.frames)-1][seqLen:]) == 1004
				}, 10*time.Second, time.Millisecond)
				stop()
				late, took := 0, 0
				for i, c := range calls {
					if c.took {
						took++
					}
					if c.whole {
						continue
					}
					late++
					if assert.Positive(t, i) {
						assert.True(t, calls[i-1].took && calls[i-1].sport == c.sport, "Prepare call %d", i)
					}
				}
				if workers == noPipe {
					assert.Zero(t, late)
				} else {
					assert.Positive(t, late)
				}
				require.Equal(t, took, u.count())
				for i, f := range u.frames {
					assert.True(t, tcpSumValid(f[seqLen:]), "frame %d", i)
				}
			})
		}
	}
}

// holdEngine is a seqEngine that seals set 0 only after it sealed all of set
// 1, so that the two seal workers finish the sets out of order.
type holdEngine struct {
	seqEngine
	set1      atomic.Int32
	set1Done  chan struct{}
	closeOnce sync.Once
}

func (e *holdEngine) Seal(f *TxFrame, virt, phy []byte) int {
	switch {
	case f.Seq < txSlots:
		<-e.set1Done
	case f.Seq < 2*txSlots:
		if e.set1.Add(1) == txSlots {
			e.closeOnce.Do(func() { close(e.set1Done) })
		}
	}
	return e.seqEngine.Seal(f, virt, phy)
}

// TestTxPipeReorder makes set 1 finish before set 0. The sender must still
// write the frames in send order.
func TestTxPipeReorder(t *testing.T) {
	pkts := []testPacket{{payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}}
	wantU := newSyncUnderlay()
	wantD := newPipeDatapath(t, &seqEngine{}, wantU, noPipe)
	writeTestPackets(t, wantD.ep, pkts)
	require.NoError(t, wantD.sendQueued())
	want := wantU.frames
	require.Greater(t, len(want), 2*txSlots)

	for _, workers := range []int{2, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			u := newSyncUnderlay()
			d := newPipeDatapath(t, &holdEngine{set1Done: make(chan struct{})}, u, workers)
			stop := run(t, d, u)
			writeTestPackets(t, d.ep, pkts)
			require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
			stop()
			require.Equal(t, len(want), u.count())
			for i := range want {
				if !assert.True(t, bytes.Equal(want[i], u.frames[i]), "frame %d", i) {
					break
				}
			}
		})
	}
}

// TestTxPipeClose closes the datapath while the pipe works. Run must return
// with no error, and all goroutines must stop.
func TestTxPipeClose(t *testing.T) {
	many := []testPacket{{payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}}
	cases := []struct {
		name    string
		workers int
		hold    bool // Seal waits until the test releases it.
		block   bool // The underlay write waits until the test closes it.
		pkts    []testPacket
	}{
		{name: "while sealing", workers: 2, hold: true, pkts: many},
		{name: "while the sender writes", workers: 1, block: true, pkts: many},
		{name: "no frames", workers: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := &seqEngine{}
			if tc.hold {
				eng.hold = make(chan struct{})
			}
			u := newSyncUnderlay()
			u.block = tc.block
			d := newPipeDatapath(t, eng, u, tc.workers)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.Run(ctx) }()
			writeTestPackets(t, d.ep, tc.pkts)
			switch {
			case tc.hold:
				require.Eventually(t, func() bool { return eng.holding.Load() > 0 }, 10*time.Second, time.Millisecond)
			case tc.block:
				require.Eventually(t, func() bool { return u.writing.Load() > 0 }, 10*time.Second, time.Millisecond)
			}
			require.NoError(t, d.Close())
			if tc.hold {
				// The worker is in Seal, so Run waits for it.
				select {
				case err := <-done:
					t.Fatalf("Run returned %v while a worker seals", err)
				case <-time.After(50 * time.Millisecond):
				}
				close(eng.hold)
			}
			u.Close()
			select {
			case err := <-done:
				assert.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return")
			}
			// A second Close is safe, and the pump sends nothing more.
			require.NoError(t, d.Close())
			n := u.count()
			writeTestPackets(t, d.ep, []testPacket{{payload: 100}})
			time.Sleep(20 * time.Millisecond)
			assert.Equal(t, n, u.count())
		})
	}
}

// TestTxPipeNoAllocs runs the steps of the send path of a pipe one after the
// other: the pump, a seal worker and the sender. They must not allocate.
func TestTxPipeNoAllocs(t *testing.T) {
	pkts, mss, size := benchPackets(true)
	plain, _, _ := benchPackets(false)
	d := newPipeDatapath(t, newPSPEngine(t), nopUnderlay{}, 1)
	p := d.pipe
	opts := stack.GSO{Type: stack.GSOTCPv6, NeedsCsum: true, MSS: uint16(mss), L3HdrLen: header.IPv6MinimumSize}
	buf := make([]byte, 0, 1<<16)
	if a := testing.AllocsPerRun(100, func() {
		buf = append(buf[:0], pkts[0]...)
		err := d.addPacket(buf, opts, header.IPv6MinimumSize)
		if err == nil {
			err = d.addPacket(plain[0], stack.GSO{}, header.IPv6MinimumSize)
		}
		if err != nil {
			t.Fatal(err)
		}
		p.flush()
		s := <-p.work
		p.sealSet(s)
		if len(s.frames) != size/mss+1 {
			t.Fatalf("%d frames, want %d", len(s.frames), size/mss+1)
		}
		if err := d.write(s.frames); err != nil {
			t.Fatal(err)
		}
		<-p.full
		s.frames, s.n = s.frames[:0], 0
		p.free <- s
	}); a != 0 {
		t.Fatalf("send path: %v allocs per run, want 0", a)
	}
}

// countUnderlay counts the frames that it gets and tells the count on n.
// ReadFrame waits until closed.
type countUnderlay struct {
	n      chan int
	closed chan struct{}
}

func (u countUnderlay) ReadFrame([]byte) (int, error) {
	<-u.closed
	return 0, net.ErrClosed
}

func (u countUnderlay) WriteFrames(frames [][]byte) (int, error) {
	u.n <- len(frames)
	return len(frames), nil
}

// benchBurst is the number of GSO packets in one write of BenchmarkTxPipe.
const benchBurst = 8

// BenchmarkPump measures the work of the send pump for each cut packet. It
// cuts GSO packets into a pipe and takes the sets back with no seal.
func BenchmarkPump(b *testing.B) {
	pkts, mss, size := benchPackets(true)
	d := newPipeDatapath(b, &seqEngine{}, nopUnderlay{}, 1)
	p := d.pipe
	opts := stack.GSO{Type: stack.GSOTCPv6, NeedsCsum: true, MSS: uint16(mss), L3HdrLen: header.IPv6MinimumSize}
	buf := make([]byte, 0, 1<<16)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for b.Loop() {
		// The cut writes into the packet, so cut a copy.
		buf = append(buf[:0], pkts[0]...)
		if err := d.addPacket(buf, opts, header.IPv6MinimumSize); err != nil {
			b.Fatal(err)
		}
		p.flush()
		for len(p.full) > 0 {
			s := <-p.full
			<-p.work
			s.n = 0
			p.free <- s
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(size/mss)), "ns/packet")
}

// BenchmarkSealSet measures the work of a seal worker for each packet of a
// set, with and without the TCP checksum.
func BenchmarkSealSet(b *testing.B) {
	for _, sum := range []bool{false, true} {
		b.Run(fmt.Sprintf("sum=%t", sum), func(b *testing.B) {
			pkts, mss, size := benchPackets(true)
			d := newPipeDatapath(b, newPSPEngine(b), nopUnderlay{}, 1)
			opts := stack.GSO{Type: stack.GSOTCPv6, NeedsCsum: true, MSS: uint16(mss), L3HdrLen: header.IPv6MinimumSize}
			require.NoError(b, d.addPacket(bytes.Clone(pkts[0]), opts, header.IPv6MinimumSize))
			s := d.pipe.cur
			for i := range s.slots[:s.n] {
				s.slots[i].csum = 0
				if sum {
					s.slots[i].csum = header.IPv6MinimumSize
				}
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				d.pipe.sealSet(s)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*s.n), "ns/packet")
		})
	}
}

// BenchmarkTxPipe writes a burst of GSO packets to the endpoint of a running
// datapath and waits until the underlay has their frames. The psp engine
// seals with a real SA.
func BenchmarkTxPipe(b *testing.B) {
	engines := []struct {
		name string
		make func() Sealer
	}{
		{"", func() Sealer { return &seqEngine{} }},
		{"psp/", func() Sealer { return newPSPEngine(b) }},
	}
	for _, eng := range engines {
		for _, workers := range []int{noPipe, 1, 2, 4} {
			b.Run(fmt.Sprintf("%sworkers=%d", eng.name, workers), func(b *testing.B) {
				benchTxPipe(b, eng.make(), workers)
			})
		}
	}
}

func benchTxPipe(b *testing.B, eng Sealer, workers int) {
	pkts, mss, size := benchPackets(true)
	u := countUnderlay{n: make(chan int, 1024), closed: make(chan struct{})}
	d := newPipeDatapath(b, eng, u, workers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(u.closed)
	go func() { _ = d.Run(ctx) }()
	segs := size / mss
	var list stack.PacketBufferList
	b.SetBytes(int64(benchBurst * size))
	b.ReportAllocs()
	for b.Loop() {
		for range benchBurst {
			for _, p := range pkts {
				list.PushBack(newPacket(p, header.IPv6MinimumSize, mss))
			}
		}
		writePackets(b, d.ep, &list)
		for got := 0; got < benchBurst*segs; {
			got += <-u.n
		}
	}
}
