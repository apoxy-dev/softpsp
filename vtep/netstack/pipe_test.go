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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// testPacket is one packet that a test writes to the endpoint.
type testPacket struct {
	v6      bool
	payload int
	mss     int // Zero writes the packet with no GSO.
}

// writeTestPackets writes pkts to ep, one write for each packet.
func writeTestPackets(t testing.TB, ep *channel.Endpoint, pkts []testPacket) {
	t.Helper()
	v4a, v4b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	v6a, v6b := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	for i, p := range pkts {
		src, dst, ipLen := v4a, v4b, header.IPv4MinimumSize
		if p.v6 {
			src, dst, ipLen = v6a, v6b, header.IPv6MinimumSize
		}
		b := tcpPacket(src, dst, uint16(1000+i), uint32(i)<<16, 7, header.TCPFlagAck, pattern(p.payload), p.mss > 0)
		var list stack.PacketBufferList
		list.PushBack(newPacket(b, ipLen, p.mss))
		writePackets(t, ep, &list)
	}
}

func TestSealWorkers(t *testing.T) {
	for procs, want := range map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 6: 1, 7: 1, 8: 2, 16: 2, 64: 2} {
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

	u := newSyncUnderlay()
	d := newPipeDatapath(t, &holdEngine{set1Done: make(chan struct{})}, u, 2)
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

// BenchmarkTxPipe writes a burst of GSO packets to the endpoint of a running
// datapath and waits until the underlay has their frames.
func BenchmarkTxPipe(b *testing.B) {
	for _, workers := range []int{noPipe, 1, 2, 4} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			pkts, mss, size := benchPackets(true)
			u := countUnderlay{n: make(chan int, 1024), closed: make(chan struct{})}
			d := newPipeDatapath(b, &seqEngine{}, u, workers)
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
		})
	}
}
