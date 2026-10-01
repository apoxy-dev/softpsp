// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/replay"
)

func newQueues(tb testing.TB, queues int) *RxTable {
	tb.Helper()
	t, err := NewRxTable(RxConfig{RowBits: 8, Queues: queues})
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

// addLane adds an SA that lane owns.
func addLane(tb testing.TB, t *RxTable, lane int) (uint32, *sender) {
	tb.Helper()
	sa := testSA()
	sa.Lane = lane
	return add(tb, t, sa)
}

// TestCopiesOnAllQueues sends copies of one packet on 16 queues at once, as
// from 16 source ports. Only one copy passes.
func TestCopiesOnAllQueues(t *testing.T) {
	for _, lane := range []int{5, AnyQueue} {
		t.Run(fmt.Sprintf("lane %d", lane), func(t *testing.T) {
			tab := newQueues(t, MaxQueues)
			for range 50 {
				spi, s := addLane(t, tab, lane)
				pkt := s.seal(t, 7, ipPacket(src4, 100), nil)
				var passed atomic.Int32
				var start, wg sync.WaitGroup
				start.Add(1)
				for i := range MaxQueues {
					wg.Go(func() {
						buf := bytes.Clone(pkt)
						start.Wait()
						if _, _, err := tab.Queue(i).Receive(buf); err == nil {
							passed.Add(1)
						}
					})
				}
				start.Done()
				wg.Wait()
				for i := range MaxQueues {
					tab.Queue(i).Drain(func([]byte, uint32) { passed.Add(1) })
				}
				st, _ := tab.Stats(spi)
				if passed.Load() != 1 || st.Packets != 1 {
					t.Fatalf("%d copies passed, stats %+v, want 1", passed.Load(), st)
				}
				if lane != AnyQueue && st.Replays != MaxQueues-1 {
					t.Fatalf("stats %+v, want %d replays", st, MaxQueues-1)
				}
				tab.Delete(spi)
			}
		})
	}
}

// TestReceiveConcurrent runs 4 queues at once. Each queue owns one SA, and gets
// a copy of every packet of every SA in its own order. Each packet must pass
// once.
func TestReceiveConcurrent(t *testing.T) {
	const queues, n = 4, 1000
	tab := newQueues(t, queues)
	var pkts [][]byte
	for q := range queues {
		_, s := addLane(t, tab, q)
		for seq := range uint32(n) {
			inner := ipPacket(src4, 64)
			binary.BigEndian.PutUint32(inner[20:], seq)
			inner[24] = byte(q)
			pkts = append(pkts, s.seal(t, seq, inner, nil))
		}
	}
	var mu sync.Mutex
	passed := map[[2]uint32]int{}
	count := func(inner []byte, _ uint32) {
		mu.Lock()
		passed[[2]uint32{uint32(inner[24]), binary.BigEndian.Uint32(inner[20:])}]++
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for q := range queues {
		wg.Go(func() {
			rq := tab.Queue(q)
			buf := make([]byte, len(pkts[0]))
			for i, j := range rand.New(rand.NewPCG(uint64(q), 0)).Perm(len(pkts)) {
				copy(buf, pkts[j])
				if inner, vni, err := rq.Receive(buf); err == nil {
					count(inner, vni)
				}
				if i%16 == 0 {
					rq.Drain(count)
				}
			}
		})
	}
	wg.Wait()
	for q := range queues {
		tab.Queue(q).Drain(count)
	}
	for k, v := range passed {
		if v != 1 {
			t.Fatalf("packet %v passed %d times", k, v)
		}
	}
	if len(passed) != queues*n {
		t.Fatalf("%d packets passed, want %d", len(passed), queues*n)
	}
}

func TestHandoffLimit(t *testing.T) {
	tab := newQueues(t, 2)
	from, owner := tab.Queue(0), tab.Queue(1)
	inner := ipPacket(src4, 60)
	var sas []*sender
	for range inboxSlots/handoffLimit + 1 {
		_, s := addLane(t, tab, 1)
		sas = append(sas, s)
	}
	send := func(i int, seq uint32, want error) {
		t.Helper()
		if _, _, err := from.Receive(sas[i].seal(t, seq, inner, nil)); !errors.Is(err, want) {
			t.Fatalf("SA %d seq %d: got %v, want %v", i, seq, err, want)
		}
	}

	// Each SA can fill handoffLimit slots. The last SA finds the inbox full.
	for i := range sas {
		for seq := range uint32(handoffLimit + 2) {
			want := ErrHandoff
			if seq >= handoffLimit || i == len(sas)-1 {
				want = ErrHandoffDrop
			}
			send(i, seq, want)
		}
	}
	passed := 0
	if n := owner.Drain(func([]byte, uint32) { passed++ }); n != inboxSlots || passed != inboxSlots {
		t.Fatalf("Drain read %d and passed %d, want %d", n, passed, inboxSlots)
	}
	if st := from.Stats(); st.Handoffs != inboxSlots || st.HandoffDrops != uint64(len(sas)*(handoffLimit+2)-inboxSlots) {
		t.Fatalf("queue stats %+v", st)
	}

	// A packet longer than the SA MTU does not go to the inbox.
	if _, _, err := from.Receive(sas[0].seal(t, 99, ipPacket(src4, testSA().MTU+1), nil)); !errors.Is(err, ErrHandoffDrop) {
		t.Fatalf("long packet: got %v, want %v", err, ErrHandoffDrop)
	}

	// Drain starts a new limit.
	send(0, 100, ErrHandoff)
	send(len(sas)-1, 100, ErrHandoff)
	if n := owner.Drain(func([]byte, uint32) { passed++ }); n != 2 || passed != inboxSlots+2 {
		t.Fatalf("Drain read %d, %d passed", n, passed)
	}
}

// TestFirstPacketOwner checks that the first packet that passes all checks
// makes its queue the owner of an AnyQueue SA.
func TestFirstPacketOwner(t *testing.T) {
	tab := newQueues(t, 4)
	spi, s := addLane(t, tab, AnyQueue)
	row := tab.rows[spi&tab.rowMask].Load()
	inner := ipPacket(src4, 60)
	forged := s.seal(t, 1, inner, nil)
	forged[len(forged)-1] ^= 1
	otherVNI := func(h *psp.Header) { h.VNI++ }

	steps := []struct {
		name  string
		queue int
		pkt   []byte
		want  error
		owner int32
	}{
		{"forged packet", 1, forged, psp.ErrAuth, AnyQueue},
		{"other VNI", 1, s.seal(t, 1, inner, otherVNI), ErrVNI, AnyQueue},
		{"first packet", 2, s.seal(t, 1, inner, nil), nil, 2},
		{"other queue", 0, s.seal(t, 2, inner, nil), ErrHandoff, 2},
		{"owner queue", 2, s.seal(t, 3, inner, nil), nil, 2},
	}
	for _, st := range steps {
		if _, _, err := tab.Queue(st.queue).Receive(st.pkt); !errors.Is(err, st.want) {
			t.Fatalf("%s: got %v, want %v", st.name, err, st.want)
		}
		if o := row.owner.Load(); o != st.owner {
			t.Fatalf("%s: owner %d, want %d", st.name, o, st.owner)
		}
	}
	if n := tab.Queue(2).Drain(func([]byte, uint32) {}); n != 1 {
		t.Fatalf("Drain read %d packets, want 1", n)
	}
	if st, _ := tab.Stats(spi); st.Packets != 3 || st.Seq != 3 || st.ICVFailures != 1 || st.Rejects != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestHandoffNoAllocs(t *testing.T) {
	tab := newQueues(t, 2)
	_, s := addLane(t, tab, 1)
	var pkts [][]byte
	for seq := range uint32(110) {
		pkts = append(pkts, s.seal(t, seq, ipPacket(src4, 1280), nil))
	}
	buf := make([]byte, len(pkts[0]))
	passed := 0
	deliver := func([]byte, uint32) { passed++ }
	i := 0
	run := func() {
		copy(buf, pkts[i])
		i++
		if _, _, err := tab.Queue(0).Receive(buf); err != ErrHandoff {
			t.Fatal(err)
		}
		tab.Queue(1).Drain(deliver)
	}
	run() // The first two runs make the buffers of the two inbox sets.
	run()
	if a := testing.AllocsPerRun(100, run); a != 0 {
		t.Fatalf("hand-off: %v allocs per run, want 0", a)
	}
	if passed != i {
		t.Fatalf("%d of %d packets passed", passed, i)
	}
}

// BenchmarkHandoff measures a packet that arrives on a queue that does not own
// its SA: the copy to the owner queue, then Receive on the owner queue.
func BenchmarkHandoff(b *testing.B) {
	tab := newQueues(b, 2)
	spi, s := addLane(b, tab, 1)
	row := tab.rows[spi&tab.rowMask].Load()
	pkts := make([][]byte, 1024)
	for i := range pkts {
		pkts[i] = s.seal(b, uint32(i), ipPacket(src4, 1280), nil)
	}
	buf := make([]byte, len(pkts[0]))
	deliver := func([]byte, uint32) {}
	b.SetBytes(1280)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		copy(buf, pkts[i])
		if _, _, err := tab.Queue(0).Receive(buf); err != ErrHandoff {
			b.Fatal(err)
		}
		if i++; i%handoffLimit == 0 {
			tab.Queue(1).Drain(deliver)
		}
		if i == len(pkts) {
			i = 0
			row.window = replay.Window{}
		}
	}
}
