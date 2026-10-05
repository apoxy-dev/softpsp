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
	seq  uint64            // Prepare runs on the send pump only.
	drop func([]byte) bool // Prepare drops these packets.
	// segs reports whether PrepareSegs takes a TCP packet. Nil takes all.
	segs    func(hdr []byte, n, size, total int) bool
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

func (e *seqEngine) PrepareSegs(hdr []byte, n, size, total int, f *TxFrame) bool {
	if e.segs != nil && !e.segs(hdr, n, size, total) {
		return false
	}
	f.Seq = e.seq
	e.seq += uint64(n)
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

func (e *seqEngine) PhyToVirt(phy, virt []byte) int { return copy(virt, phy[seqLen:]) }

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

func (e *pspEngine) PrepareSegs(_ []byte, n, _, _ int, f *TxFrame) bool {
	seq, err := e.tx.ReserveN(n)
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

func (u *syncUnderlay) sent() [][][]byte { return [][][]byte{u.frames} }

// sendUnderlay is an underlay that keeps a copy of each frame that it sent.
type sendUnderlay interface {
	Underlay
	Close()
	count() int
	// sent returns the frames of each lane, in send order. An underlay with no
	// lanes has one.
	sent() [][][]byte
}

// noLanes is the lanes of newSendUnderlay for an underlay that copies the
// frames in the write.
const noLanes = 0

// newSendUnderlay returns a keepUnderlay with lanes lanes, or a syncUnderlay
// for noLanes.
func newSendUnderlay(lanes int) sendUnderlay {
	if lanes == noLanes {
		return newSyncUnderlay()
	}
	return newKeepUnderlay(lanes)
}

// laneEngine is a Sealer that puts the lane of the flow before each frame of
// its Sealer, as the engine of apoxy does. The lane is the source port modulo
// lanes, and the frames of the engine go on lane 0.
type laneEngine struct {
	Sealer
	lanes int
}

func (e laneEngine) Overhead() int { return 1 + e.Sealer.Overhead() }

func (e laneEngine) Prepare(virt []byte, f *TxFrame) bool {
	f.Lane = int(srcPort(virt)) % e.lanes
	return e.Sealer.Prepare(virt, f)
}

func (e laneEngine) PrepareSegs(hdr []byte, n, size, total int, f *TxFrame) bool {
	f.Lane = int(srcPort(hdr)) % e.lanes
	return e.Sealer.PrepareSegs(hdr, n, size, total, f)
}

func (e laneEngine) Seal(f *TxFrame, virt, phy []byte) int {
	n := e.Sealer.Seal(f, virt, phy[1:])
	if n == 0 {
		return 0
	}
	phy[0] = byte(f.Lane)
	return 1 + n
}

func (e laneEngine) VirtToPhy(virt, phy []byte) (int, bool) {
	var f TxFrame
	if !e.Prepare(virt, &f) {
		return 0, false
	}
	return e.Seal(&f, virt, phy), false
}

func (e laneEngine) ToPhy(phy []byte) int {
	n := e.Sealer.ToPhy(phy[1:])
	if n == 0 {
		return 0
	}
	phy[0] = 0
	return 1 + n
}

// byLane returns the frames of each of n lanes, in the order of frames. The
// first byte of a frame is its lane. For noLanes, all frames are one lane.
func byLane(frames [][]byte, n int) [][][]byte {
	if n == noLanes {
		return [][][]byte{frames}
	}
	out := make([][][]byte, n)
	for _, f := range frames {
		out[f[0]] = append(out[f[0]], f)
	}
	return out
}

// keepUnderlay is a Keeper with one sender for each lane, as the underlay of
// apoxy is. The first byte of a frame is its lane. A sender keeps the frames
// of a write, and copies and releases them later.
type keepUnderlay struct {
	mu      sync.Mutex
	cond    *sync.Cond
	queue   [][]keptFrames // The writes that each sender keeps, in write order.
	lanes   [][][]byte     // Copies of the frames that each lane sent, in send order.
	n       int            // The frames in lanes.
	kept    int            // The frames in queue and with the senders.
	users   map[*Kept]int  // The senders that keep frames of each write.
	changed int            // Frames that changed while a sender kept them.
	stopped bool

	writeMax int           // When set, a write takes at most writeMax frames.
	slow     bool          // A sender waits a random time before it sends.
	hold     chan struct{} // When set, the senders wait until it closes.
	keeps    atomic.Int64  // Keep calls.
	releases atomic.Int64  // Release calls.
	closed   chan struct{}
	wg       sync.WaitGroup
}

// keptFrames is the frames of one write for one lane, and their copies from
// the time of the write.
type keptFrames struct {
	frames, was [][]byte
	k           *Kept
}

func newKeepUnderlay(lanes int) *keepUnderlay {
	u := &keepUnderlay{queue: make([][]keptFrames, lanes), lanes: make([][][]byte, lanes), users: map[*Kept]int{}, closed: make(chan struct{})}
	u.cond = sync.NewCond(&u.mu)
	for l := range lanes {
		u.wg.Go(func() { u.send(l) })
	}
	return u
}

func (u *keepUnderlay) ReadFrame([]byte) (int, error) {
	<-u.closed
	return 0, net.ErrClosed
}

// WriteFrames copies the frames at once. A datapath with no pipe calls it.
func (u *keepUnderlay) WriteFrames(frames [][]byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopped {
		return 0, net.ErrClosed
	}
	for _, f := range frames {
		u.lanes[f[0]] = append(u.lanes[f[0]], bytes.Clone(f))
	}
	u.n += len(frames)
	return len(frames), nil
}

// WriteKept gives the frames to the senders of their lanes with no copy. Each
// sender is one user of k.
func (u *keepUnderlay) WriteKept(frames [][]byte, k *Kept) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopped {
		return 0, net.ErrClosed
	}
	if u.writeMax > 0 {
		frames = frames[:min(len(frames), u.writeMax)]
	}
	for l := range u.queue {
		kf := keptFrames{k: k}
		for _, f := range frames {
			if int(f[0]) == l {
				kf.frames, kf.was = append(kf.frames, f), append(kf.was, bytes.Clone(f))
			}
		}
		if len(kf.frames) > 0 {
			k.Keep()
			u.keeps.Add(1)
			u.users[k]++
			u.queue[l] = append(u.queue[l], kf)
		}
	}
	u.kept += len(frames)
	u.cond.Broadcast()
	return len(frames), nil
}

// send is the sender of lane l. It stops after Close, when its queue is empty.
func (u *keepUnderlay) send(l int) {
	for {
		u.mu.Lock()
		for len(u.queue[l]) == 0 && !u.stopped {
			u.cond.Wait()
		}
		if len(u.queue[l]) == 0 {
			u.mu.Unlock()
			return
		}
		kf := u.queue[l][0]
		u.queue[l] = u.queue[l][1:]
		u.mu.Unlock()
		if u.hold != nil {
			<-u.hold
		}
		if u.slow {
			time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond)
		}
		u.mu.Lock()
		for i, f := range kf.frames {
			if !bytes.Equal(f, kf.was[i]) {
				u.changed++
			}
		}
		u.lanes[l] = append(u.lanes[l], kf.was...)
		u.n += len(kf.frames)
		u.kept -= len(kf.frames)
		if u.users[kf.k]--; u.users[kf.k] == 0 {
			delete(u.users, kf.k)
		}
		u.mu.Unlock()
		kf.k.Release()
		u.releases.Add(1)
	}
}

// Close stops the underlay and waits until the senders sent all frames.
func (u *keepUnderlay) Close() {
	u.mu.Lock()
	if !u.stopped {
		u.stopped = true
		close(u.closed)
		u.cond.Broadcast()
	}
	u.mu.Unlock()
	u.wg.Wait()
}

func (u *keepUnderlay) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.n
}

// keeping returns the number of frames that the senders keep, and the number
// of writes that they are from.
func (u *keepUnderlay) keeping() (frames, writes int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.kept, len(u.users)
}

func (u *keepUnderlay) sent() [][][]byte { return u.lanes }

// waitFree waits until each set of the pipe of d is free, or is the empty set
// of the pump. A pipe that sent all its frames must get there.
func waitFree(t *testing.T, d *Datapath) {
	t.Helper()
	if p := d.pipe; p != nil {
		require.Eventually(t, func() bool { return len(p.free) >= cap(p.free)-1 }, 10*time.Second, time.Millisecond, "free sets")
	}
}

// checkSent checks the frames of a datapath that stopped: each lane of u sent
// the frames of want, in order. No frame changed while u kept it, and u
// released all frames.
func checkSent(t *testing.T, u sendUnderlay, want [][][]byte) {
	t.Helper()
	got := u.sent()
	require.Len(t, got, len(want))
	for l := range want {
		if !assert.Len(t, got[l], len(want[l]), "lane %d", l) {
			continue
		}
		for i := range want[l] {
			if !assert.True(t, bytes.Equal(want[l][i], got[l][i]), "lane %d, frame %d", l, i) {
				break
			}
		}
	}
	if k, ok := u.(*keepUnderlay); ok {
		assert.Zero(t, k.changed, "frames that changed while the underlay kept them")
		assert.Equal(t, k.keeps.Load(), k.releases.Load(), "Keep and Release calls")
	}
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
func run(t *testing.T, d *Datapath, u interface{ Close() }) func() {
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
	// flat writes a packet with GSO as newPacket makes it, and not as the
	// stack makes it. The pump must cut a flat packet.
	flat bool
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

// buffer returns the packet buffer of packet i of a test.
func (p testPacket) buffer(t testing.TB, i int) *stack.PacketBuffer {
	b, ipLen := p.build(t, i)
	if p.mss > 0 && !p.flat {
		return stackPacket(b, ipLen, p.mss, 1)
	}
	return newPacket(b, ipLen, p.mss)
}

// writeTestPackets writes pkts to ep, one write for each packet.
func writeTestPackets(t testing.TB, ep *channel.Endpoint, pkts []testPacket) {
	t.Helper()
	for i, p := range pkts {
		var list stack.PacketBufferList
		list.PushBack(p.buffer(t, i))
		writePackets(t, ep, &list)
	}
}

// srcPort returns the source port of the IP packet, or of the headers, v.
func srcPort(v []byte) uint16 {
	if v[0]>>4 == header.IPv6Version {
		return binary.BigEndian.Uint16(v[header.IPv6MinimumSize:])
	}
	return binary.BigEndian.Uint16(v[header.IPv4MinimumSize:])
}

// tcpSeq returns the offset of the TCP packet v in the data of its test
// packet.
func tcpSeq(v []byte) int {
	ipLen := header.IPv4MinimumSize
	if v[0]>>4 == header.IPv6Version {
		ipLen = header.IPv6MinimumSize
	}
	return int(binary.BigEndian.Uint32(v[ipLen+4:]) & 0xffff)
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

// TestNewPipe checks that New makes a pipe only for a Sealer, and that only a
// pipe with a Keeper has the sets of txKeepSets.
func TestNewPipe(t *testing.T) {
	want := sealWorkers(runtime.GOMAXPROCS(0))
	for _, tc := range []struct {
		name string
		eng  Sealer
		u    Underlay
		pipe bool
		sets int
	}{
		{"sealer", &seqEngine{}, newSyncUnderlay(), want > 0, txSets + 2*want},
		{"sealer and keeper", &seqEngine{}, &nopKeeper{}, want > 0, txSets + 2*want + txKeepSets},
		{"plain engine", nil, newSyncUnderlay(), false, 0},
		{"plain engine and keeper", nil, &nopKeeper{}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Engine: fakeEngine{}, Endpoint: channel.New(1, testMTU, ""), Underlay: tc.u}
			if tc.eng != nil {
				cfg.Engine = tc.eng
			}
			d, err := New(cfg)
			require.NoError(t, err)
			defer d.Close()
			assert.Equal(t, tc.pipe, d.pipe != nil)
			if d.pipe != nil {
				assert.Equal(t, want, d.pipe.workers)
				assert.Equal(t, tc.sets, cap(d.pipe.free))
				assert.Equal(t, tc.sets, len(d.pipe.free))
			}
		})
	}
}

// TestTxPipe sends packets through a datapath with a send pipe. The frames
// must equal the frames of a datapath with no pipe: the same frames, in send
// order, also when the seal workers finish the sets in another order, when
// Prepare or Seal drops frames, when PrepareSegs refuses TCP packets, and
// when the engine has frames of its own.
func TestTxPipe(t *testing.T) {
	none := func([]byte, int, int, int) bool { return false }
	// Five TCP packets with GSO, each of one flow, and a packet with no GSO.
	flows := []testPacket{{payload: 9000, mss: 500}, {payload: 60_000, mss: 400}, {payload: 30_000, mss: 700}, {payload: 60_000, mss: 400}, {payload: 5000, mss: 1000}, {payload: 50}}
	cases := []struct {
		name string
		pkts []testPacket
		drop func([]byte) bool
		segs func(hdr []byte, n, size, total int) bool
		fail func(uint64) bool
		keep int
	}{
		{name: "GSO and plain", pkts: []testPacket{{payload: 4500, mss: 1000}, {v6: true, payload: 10}, {payload: 1200}, {v6: true, payload: 3000, mss: 1000}}},
		{name: "many sets", pkts: []testPacket{{payload: 60_000, mss: 400}, {v6: true, payload: 60_000, mss: 400}, {payload: 60_000, mss: 400}}},
		{name: "small packets", pkts: []testPacket{{mss: 1000}, {v6: true, payload: 1, mss: 1000}, {payload: 100, mss: 7}, {v6: true, mss: 1000}}},
		{name: "flat packets", pkts: []testPacket{{payload: 4500, mss: 1000, flat: true}, {v6: true, payload: 60_000, mss: 400}, {v6: true, payload: 60_000, mss: 400, flat: true}}},
		{name: "Prepare drops", pkts: []testPacket{{payload: 60_000, mss: 400}, {payload: 50}}, segs: none, drop: func(v []byte) bool { return v[len(v)-1]%5 == 0 }},
		{name: "Seal drops", pkts: []testPacket{{payload: 60_000, mss: 400}, {payload: 50}}, fail: func(seq uint64) bool { return seq%7 == 3 }},
		{name: "engine frames", pkts: []testPacket{{payload: 4000, mss: 1000}}, keep: 3},
		{name: "all refused", pkts: flows, segs: none},
		// The route of the flows 2 and 3 goes away between two TCP packets.
		{name: "no route", pkts: flows, segs: func(h []byte, _, _, _ int) bool { p := srcPort(h); return p != 1002 && p != 1003 },
			drop: func(v []byte) bool { p := srcPort(v); return p == 1002 || p == 1003 }},
		// The SA of flow 1 goes away after 70 packets of its TCP packet, in its second set.
		{name: "no SA in a run", pkts: flows, segs: func(h []byte, _, _, _ int) bool { return srcPort(h) != 1001 },
			drop: func(v []byte) bool { return srcPort(v) == 1001 && tcpSeq(v) >= 70*400 }},
	}
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 2, 4} {
			for _, lanes := range []int{noLanes, 1, 3} {
				t.Run(fmt.Sprintf("%s/workers=%d/lanes=%d", tc.name, workers, lanes), func(t *testing.T) {
					engine := func() Sealer {
						e := &seqEngine{drop: tc.drop, segs: tc.segs, fail: tc.fail, shuffle: workers > 0}
						for i := range tc.keep {
							e.keep = append(e.keep, pattern(100+i))
						}
						if lanes != noLanes {
							return laneEngine{e, lanes}
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

					u := newSendUnderlay(lanes)
					if k, ok := u.(*keepUnderlay); ok {
						k.slow = true
					}
					d := newPipeDatapath(t, engine(), u, workers)
					stop := run(t, d, u)
					writeTestPackets(t, d.ep, tc.pkts)
					require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
					waitFree(t, d)
					stop()
					checkSent(t, u, byLane(want, lanes))
				})
			}
		}
	}
}

// TestTxPipeBytes seals packets with a real SA, with and without a send pipe,
// and opens the frames. Each inner packet must equal a packet that tcpPacket
// makes whole, in send order. With lanes, a Keeper sends the frames of each
// flow on one lane, and each lane must have its packets in send order.
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
		{name: "flat packets", pkts: []testPacket{{payload: 4500, mss: 1000, flat: true}, {v6: true, payload: 60_001, mss: 401, flat: true}, {payload: 2501, mss: 999}}},
		{name: "many flows", pkts: []testPacket{{payload: 60_000, mss: 400}, {v6: true, payload: 60_001, mss: 401}, {payload: 70}, {payload: 30_000, mss: 1208}, {udp: true, payload: 100}, {v6: true, payload: 60_000, mss: 400}, {payload: 9000, mss: 1000, flat: true}}},
	}
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 2, 4} {
			for _, lanes := range []int{noLanes, 1, 3} {
				t.Run(fmt.Sprintf("%s/workers=%d/lanes=%d", tc.name, workers, lanes), func(t *testing.T) {
					want := wantPackets(t, tc.pkts)
					eng := newPSPEngine(t)
					var sealer Sealer = eng
					if lanes != noLanes {
						sealer = laneEngine{eng, lanes}
					}
					u := newSendUnderlay(lanes)
					d := newPipeDatapath(t, sealer, u, workers)
					stop := run(t, d, u)
					writeTestPackets(t, d.ep, tc.pkts)
					require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
					waitFree(t, d)
					stop()
					require.Equal(t, len(want), u.count())
					if lanes == noLanes {
						for i, f := range u.sent()[0] {
							if !assert.True(t, bytes.Equal(want[i], eng.open(t, f)), "packet %d", i) {
								break
							}
						}
						return
					}
					// The lanes are not in one order, so no replay window checks the frames.
					wantLanes := make([][][]byte, lanes)
					for _, p := range want {
						l := int(srcPort(p)) % lanes
						wantLanes[l] = append(wantLanes[l], p)
					}
					got := u.sent()
					for l := range got {
						for i, f := range got[l] {
							require.Equal(t, byte(l), f[0])
							inner, _, err := eng.rx.Open(f[1:])
							require.NoError(t, err)
							got[l][i] = inner
						}
					}
					checkSent(t, u, wantLanes)
				})
			}
		}
	}
}

// TestTxPipePrepare checks the calls of the engine. PrepareSegs gets each TCP
// packet with GSO once. Prepare gets the other packets, and each one is whole.
func TestTxPipePrepare(t *testing.T) {
	pkts := []testPacket{{payload: 9000, mss: 1000}, {v6: true, payload: 9000, mss: 1000}, {payload: 500}, {payload: 9500, mss: 1000}, {payload: 700, mss: 1000}}
	cases := []struct {
		name   string
		refuse func(sport uint16) bool    // PrepareSegs refuses these flows.
		drop   func(v []byte, n int) bool // n is the number of Prepare calls before this one.
		segs   int                        // TCP packets that PrepareSegs takes.
		calls  int                        // Prepare calls with a pipe.
	}{
		{name: "no drops", segs: 4, calls: 1},
		{name: "one flow has no route", refuse: func(p uint16) bool { return p == 1001 }, drop: func(v []byte, _ int) bool { return srcPort(v) == 1001 }, segs: 3, calls: 10},
		{name: "no SA in a run", refuse: func(p uint16) bool { return p == 1003 }, drop: func(v []byte, _ int) bool { return srcPort(v) == 1003 && tcpSeq(v) >= 4000 }, segs: 3, calls: 11},
		{name: "each fifth packet", refuse: func(uint16) bool { return true }, drop: func(_ []byte, n int) bool { return n%5 == 2 }, calls: 30},
	}
	type call struct{ whole, took bool }
	for _, tc := range cases {
		for _, workers := range []int{noPipe, 1, 4} {
			t.Run(fmt.Sprintf("%s/workers=%d", tc.name, workers), func(t *testing.T) {
				var calls []call
				segs, took := 0, 0
				eng := &seqEngine{
					drop: func(v []byte) bool {
						c := call{whole: tcpSumValid(v), took: tc.drop == nil || !tc.drop(v, len(calls))}
						calls = append(calls, c)
						if c.took {
							took++
						}
						return !c.took
					},
					segs: func(hdr []byte, n, size, total int) bool {
						p := pkts[srcPort(hdr)-1000]
						hdrLen := header.IPv4MinimumSize + header.TCPMinimumSize + tcpOpts
						if p.v6 {
							hdrLen += header.IPv6MinimumSize - header.IPv4MinimumSize
						}
						assert.Len(t, hdr, hdrLen)
						assert.Equal(t, (p.payload+p.mss-1)/p.mss, n)
						assert.Equal(t, hdrLen+min(p.mss, p.payload), size)
						assert.Equal(t, n*hdrLen+p.payload, total)
						if tc.refuse != nil && tc.refuse(srcPort(hdr)) {
							return false
						}
						segs++
						took += n
						return true
					},
				}
				u := newSyncUnderlay()
				d := newPipeDatapath(t, eng, u, workers)
				stop := run(t, d, u)
				writeTestPackets(t, d.ep, pkts)
				// No test case drops the last packet.
				require.Eventually(t, func() bool {
					u.mu.Lock()
					defer u.mu.Unlock()
					return len(u.frames) > 0 && srcPort(u.frames[len(u.frames)-1][seqLen:]) == 1004
				}, 10*time.Second, time.Millisecond)
				stop()
				if workers == noPipe {
					assert.Zero(t, segs)
					assert.Len(t, calls, 30)
				} else {
					assert.Equal(t, tc.segs, segs)
					assert.Len(t, calls, tc.calls)
				}
				for i, c := range calls {
					assert.True(t, c.whole, "Prepare call %d", i)
				}
				require.Equal(t, took, u.count())
				for i, f := range u.frames {
					assert.True(t, tcpSumValid(f[seqLen:]), "frame %d", i)
				}
			})
		}
	}
}

// TestTxPipeTooLarge sends a TCP packet whose packets are larger than the MTU
// of the endpoint. The pipe drops them and does not call the engine.
func TestTxPipeTooLarge(t *testing.T) {
	for _, flat := range []bool{false, true} {
		t.Run(fmt.Sprintf("flat=%t", flat), func(t *testing.T) {
			calls := 0
			eng := &seqEngine{
				drop: func(v []byte) bool { calls++; return false },
				segs: func([]byte, int, int, int) bool { calls++; return true },
			}
			u := newSyncUnderlay()
			d := newPipeDatapath(t, eng, u, 2)
			stop := run(t, d, u)
			writeTestPackets(t, d.ep, []testPacket{{payload: 2 * testMTU, mss: testMTU, flat: flat}, {payload: 300, mss: 100, flat: flat}})
			require.Eventually(t, func() bool { return u.count() >= 3 }, 10*time.Second, time.Millisecond)
			stop()
			assert.Equal(t, 3, u.count())
			// One PrepareSegs call, or one Prepare call for each small packet.
			assert.Equal(t, map[bool]int{false: 1, true: 3}[flat], calls)
			for _, f := range u.frames {
				assert.Equal(t, uint16(1001), srcPort(f[seqLen:]))
			}
		})
	}
}

// TestTxPipeRelease checks that the pipe releases each packet of the endpoint
// that it took, when it sends the frames and when the datapath closes first.
// A Keeper must also get one Release for each Keep.
func TestTxPipeRelease(t *testing.T) {
	pkts := []testPacket{{payload: 60_000, mss: 400}, {v6: true, payload: 9000, mss: 1000}, {payload: 500}, {mss: 1000}, {payload: 60_000, mss: 400}, {payload: 60_000, mss: 400, flat: true}}
	for _, closed := range []bool{false, true} {
		for _, workers := range []int{1, 4} {
			for _, lanes := range []int{noLanes, 3} {
				t.Run(fmt.Sprintf("closed=%t/workers=%d/lanes=%d", closed, workers, lanes), func(t *testing.T) {
					seq := &seqEngine{}
					if closed {
						seq.hold = make(chan struct{})
					}
					var eng Sealer = seq
					if lanes != noLanes {
						eng = laneEngine{seq, lanes}
					}
					u := newSendUnderlay(lanes)
					d := newPipeDatapath(t, eng, u, workers)
					stop := run(t, d, u)
					// The test keeps one reference to each packet.
					bufs := make([]*stack.PacketBuffer, 0, 3*len(pkts))
					for range 3 {
						for i, p := range pkts {
							pkb := p.buffer(t, i)
							bufs = append(bufs, pkb.IncRef())
							var list stack.PacketBufferList
							list.PushBack(pkb)
							writePackets(t, d.ep, &list)
						}
					}
					if closed {
						require.Eventually(t, func() bool { return seq.holding.Load() > 0 }, 10*time.Second, time.Millisecond)
						require.NoError(t, d.Close())
						close(seq.hold)
					} else {
						require.Eventually(t, func() bool { return u.count() >= 3*(150+9+1+1+150+150) }, 10*time.Second, time.Millisecond)
					}
					stop()
					// The packets that the pump did not read are in the endpoint.
					for pkb := d.ep.Read(); pkb != nil; pkb = d.ep.Read() {
						pkb.DecRef()
					}
					for i, pkb := range bufs {
						assert.Equal(t, int64(1), pkb.ReadRefs(), "packet %d", i)
						pkb.DecRef()
					}
					if k, ok := u.(*keepUnderlay); ok {
						assert.Equal(t, k.keeps.Load(), k.releases.Load(), "Keep and Release calls")
					}
				})
			}
		}
	}
}

// TestTxPipeKeep makes a Keeper hold the frames of more packets than the sets
// of the pipe have. The pump must wait when all sets have users, and no frame
// can change before its Release. Each set must be free after its last Release,
// also when the datapath closed first.
func TestTxPipeKeep(t *testing.T) {
	const lanes = 3
	// 60 packets of 150 frames each: 141 sets.
	pkts := make([]testPacket, 60)
	for i := range pkts {
		pkts[i] = testPacket{payload: 60_000, mss: 400}
	}
	wantU := newSyncUnderlay()
	wantD := newPipeDatapath(t, laneEngine{&seqEngine{}, lanes}, wantU, noPipe)
	writeTestPackets(t, wantD.ep, pkts)
	require.NoError(t, wantD.sendQueued())
	want := wantU.frames

	cases := []struct {
		name string
		// closed closes the datapath while the underlay keeps the frames.
		closed  bool
		workers int
		// writeMax makes each write of the underlay short.
		writeMax int
	}{
		{name: "release", workers: 1},
		{name: "release, 4 workers", workers: 4},
		{name: "release, short writes", workers: 2, writeMax: 7},
		{name: "close before the release", closed: true, workers: 1},
		{name: "close before the release, 4 workers", closed: true, workers: 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := newKeepUnderlay(lanes)
			u.hold, u.writeMax = make(chan struct{}), tc.writeMax
			d := newPipeDatapath(t, laneEngine{&seqEngine{}, lanes}, u, tc.workers)
			sets := cap(d.pipe.free)
			require.Equal(t, txSets+2*tc.workers+txKeepSets, sets)
			stop := run(t, d, u)
			bufs := make([]*stack.PacketBuffer, len(pkts))
			for i, p := range pkts {
				bufs[i] = p.buffer(t, i).IncRef()
				var list stack.PacketBufferList
				list.PushBack(bufs[i])
				writePackets(t, d.ep, &list)
			}
			// The underlay keeps the frames of all sets, and then the pump waits.
			require.Eventually(t, func() bool { _, n := u.keeping(); return n == sets }, 10*time.Second, time.Millisecond)
			kept, _ := u.keeping()
			time.Sleep(20 * time.Millisecond)
			frames, n := u.keeping()
			require.Equal(t, sets, n)
			require.Equal(t, kept, frames)
			require.Less(t, kept, len(want))
			require.Empty(t, d.pipe.free)
			require.Zero(t, u.count())

			if tc.closed {
				require.NoError(t, d.Close())
				// The seal workers and the sender stop while the underlay keeps the frames.
				require.Eventually(t, func() bool {
					d.pipe.mu.Lock()
					defer d.pipe.mu.Unlock()
					return d.pipe.closing
				}, 10*time.Second, time.Millisecond)
				close(u.hold)
				stop()
				checkSent(t, u, byLane(want[:kept], lanes))
				// The underlay kept all sets, so all of them are free now.
				require.Len(t, d.pipe.free, sets)
			} else {
				close(u.hold)
				require.Eventually(t, func() bool { return u.count() >= len(want) }, 10*time.Second, time.Millisecond)
				waitFree(t, d)
				stop()
				checkSent(t, u, byLane(want, lanes))
			}
			for pkb := d.ep.Read(); pkb != nil; pkb = d.ep.Read() {
				pkb.DecRef()
			}
			for i, pkb := range bufs {
				assert.Equal(t, int64(1), pkb.ReadRefs(), "packet %d", i)
				pkb.DecRef()
			}
		})
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

// refuseEngine is a pspEngine whose PrepareSegs refuses all TCP packets, so
// that the pump cuts them.
type refuseEngine struct{ *pspEngine }

func (refuseEngine) PrepareSegs([]byte, int, int, int, *TxFrame) bool { return false }

// nopKeeper drops the frames that it gets. It is a user of the frames of each
// write until release.
type nopKeeper struct {
	nopUnderlay
	kept []*Kept
}

func (u *nopKeeper) WriteKept(frames [][]byte, k *Kept) (int, error) {
	k.Keep()
	u.kept = append(u.kept, k)
	return len(frames), nil
}

func (u *nopKeeper) release() {
	for _, k := range u.kept {
		k.Release()
	}
	u.kept = u.kept[:0]
}

// TestTxPipeNoAllocs runs the steps of the send path of a pipe one after the
// other: the pump, a seal worker and the sender. They must not allocate, when
// a seal worker cuts the TCP packet and when the pump cuts it, and when the
// underlay copies the frames and when it keeps them.
func TestTxPipeNoAllocs(t *testing.T) {
	pkts, mss, size := benchPackets(true)
	plain, _, _ := benchPackets(false)
	for _, tc := range []struct {
		name string
		eng  func(*pspEngine) Sealer
		runs int
		keep bool
	}{
		{"seal worker cuts", func(e *pspEngine) Sealer { return e }, 1, false},
		{"pump cuts", func(e *pspEngine) Sealer { return refuseEngine{e} }, 0, false},
		{"seal worker cuts, underlay keeps", func(e *pspEngine) Sealer { return e }, 1, true},
		{"pump cuts, underlay keeps", func(e *pspEngine) Sealer { return refuseEngine{e} }, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var u Underlay = nopUnderlay{}
			keeper := &nopKeeper{kept: make([]*Kept, 0, 1)}
			if tc.keep {
				u = keeper
			}
			d := newPipeDatapath(t, tc.eng(newPSPEngine(t)), u, 1)
			p := d.pipe
			c := &segCut{p: p}
			// The pipe takes its own references, so the test sends the packets
			// again. A race build allocates for some views, so the data is one.
			gso := stackPacket(pkts[0], header.IPv6MinimumSize, mss, size)
			defer gso.DecRef()
			one := newPacket(plain[0], header.IPv6MinimumSize, 0)
			defer one.DecRef()
			if a := testing.AllocsPerRun(100, func() {
				err := d.addPkt(gso)
				if err == nil {
					err = d.addPkt(one)
				}
				if err != nil {
					t.Fatal(err)
				}
				s := p.cur
				if len(s.runs) != tc.runs {
					t.Fatalf("%d runs, want %d", len(s.runs), tc.runs)
				}
				p.flush()
				<-p.work
				p.sealSet(s, c)
				if len(s.frames) != size/mss+1 {
					t.Fatalf("%d frames, want %d", len(s.frames), size/mss+1)
				}
				<-p.full
				if err := p.write(s); err != nil {
					t.Fatal(err)
				}
				// The set is free only after the underlay releases it.
				if tc.keep && len(p.free) != cap(p.free)-1 {
					t.Fatalf("%d free sets before the release, want %d", len(p.free), cap(p.free)-1)
				}
				keeper.release()
				if len(p.free) != cap(p.free) {
					t.Fatalf("%d free sets, want %d", len(p.free), cap(p.free))
				}
			}); a != 0 {
				t.Fatalf("send path: %v allocs per run, want 0", a)
			}
		})
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

// countKeeper is a countUnderlay that is a Keeper. It keeps no frame after a
// write.
type countKeeper struct{ countUnderlay }

func (u countKeeper) WriteKept(frames [][]byte, k *Kept) (int, error) {
	k.Keep()
	u.n <- len(frames)
	k.Release()
	return len(frames), nil
}

// benchBurst is the number of GSO packets in one write of BenchmarkTxPipe.
const benchBurst = 8

// BenchmarkPump measures the work of the send pump for each cut packet: when
// the pipe takes the GSO packet whole, and when the pump cuts it. No seal.
func BenchmarkPump(b *testing.B) {
	for _, cut := range []string{"worker", "pump"} {
		b.Run("cut="+cut, func(b *testing.B) {
			pkts, mss, size := benchPackets(true)
			eng := &seqEngine{}
			if cut == "pump" {
				eng.segs = func([]byte, int, int, int) bool { return false }
			}
			d := newPipeDatapath(b, eng, nopUnderlay{}, 1)
			p := d.pipe
			pkt := stackPacket(pkts[0], header.IPv6MinimumSize, mss, 1)
			defer pkt.DecRef()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := d.addPkt(pkt); err != nil {
					b.Fatal(err)
				}
				p.flush()
				for len(p.full) > 0 {
					s := <-p.full
					<-p.work
					s.drop()
					p.free <- s
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*(size/mss)), "ns/packet")
		})
	}
}

// BenchmarkSealSet measures the work of a seal worker for each packet of a
// set: when it cuts the packets of a GSO packet, and when the pump cut them.
func BenchmarkSealSet(b *testing.B) {
	for _, cut := range []string{"worker", "pump"} {
		b.Run("cut="+cut, func(b *testing.B) {
			pkts, mss, size := benchPackets(true)
			var eng Sealer = newPSPEngine(b)
			if cut == "pump" {
				eng = refuseEngine{eng.(*pspEngine)}
			}
			d := newPipeDatapath(b, eng, nopUnderlay{}, 1)
			pkt := stackPacket(pkts[0], header.IPv6MinimumSize, mss, 1)
			defer pkt.DecRef()
			require.NoError(b, d.addPkt(pkt))
			s := d.pipe.cur
			n := s.n
			require.Equal(b, size/mss, n)
			// A cut releases the packet of a run and moves its place. Thus the
			// set gets the runs again after each seal.
			runs := append([]txRun(nil), s.runs...)
			c := &segCut{p: d.pipe}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				d.pipe.sealSet(s, c)
				for i := range runs {
					pkt.IncRef()
					s.runs[i] = runs[i]
				}
			}
			s.drop()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/packet")
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
				benchTxPipe(b, eng.make(), workers, false)
			})
		}
	}
	b.Run("psp/workers=4/keep", func(b *testing.B) { benchTxPipe(b, newPSPEngine(b), 4, true) })
}

func benchTxPipe(b *testing.B, eng Sealer, workers int, keep bool) {
	pkts, mss, size := benchPackets(true)
	cu := countUnderlay{n: make(chan int, 1024), closed: make(chan struct{})}
	var u Underlay = cu
	if keep {
		u = countKeeper{cu}
	}
	d := newPipeDatapath(b, eng, u, workers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer close(cu.closed)
	go func() { _ = d.Run(ctx) }()
	segs := size / mss
	var list stack.PacketBufferList
	b.SetBytes(int64(benchBurst * size))
	b.ReportAllocs()
	for b.Loop() {
		for range benchBurst {
			for _, p := range pkts {
				list.PushBack(stackPacket(p, header.IPv6MinimumSize, mss, 1))
			}
		}
		writePackets(b, d.ep, &list)
		for got := 0; got < benchBurst*segs; {
			got += <-cu.n
		}
	}
}
