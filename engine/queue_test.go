// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TestOpenParallel opens each batch of packets on several goroutines, while one
// goroutine accepts the batch before it in packet order, as a read loop with
// helpers. The results must be the same as from Receive in packet order.
func TestOpenParallel(t *testing.T) {
	const batch, rounds = 64, 40
	cases := []struct {
		name    string
		lane    int
		workers int
	}{
		{"owner queue", 0, 4},
		{"any queue", AnyQueue, 4},
		{"one worker", 0, 1},
	}
	type slot struct {
		pkt   []byte
		inner []byte
		o     Opened
		err   error
		want  error
		id    uint32
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newQueues(t, 1)
			q := tab.Queue(0)
			var spis [2]uint32
			var ss [2]*sender
			for i := range ss {
				spis[i], ss[i] = addLane(t, tab, tc.lane)
			}
			var seq [2]uint32
			var want [2]RxStats
			// build fills b with round r. Each SA gets a forged packet, a copy
			// of an earlier packet and a packet from a source that is not
			// allowed. Those do not use a sequence number.
			build := func(b []slot, r int) {
				for i := range b {
					sa, sl := i%2, &b[i]
					sl.id = uint32(r*batch + i)
					inner := ipPacket(src4, 60)
					binary.BigEndian.PutUint32(inner[20:], sl.id)
					sl.want = nil
					switch i % 16 {
					case 5:
						sl.pkt = ss[sa].seal(t, seq[sa], inner, nil)
						sl.pkt[len(sl.pkt)-1] ^= 1
						sl.want = psp.ErrAuth
						want[sa].ICVFailures++
					case 9:
						sl.pkt = bytes.Clone(b[i-2].pkt)
						sl.id = b[i-2].id
						sl.want = ErrReplay
						want[sa].Replays++
					case 12:
						sl.pkt = ss[sa].seal(t, seq[sa], ipPacket(netip.MustParseAddr("10.2.0.5"), 60), nil)
						sl.want = ErrSource
						want[sa].Rejects++
					default:
						sl.pkt = ss[sa].seal(t, seq[sa], inner, nil)
						want[sa].Packets++
						want[sa].Seq = seq[sa]
						seq[sa]++
					}
				}
			}
			open := func(b []slot) *sync.WaitGroup {
				var wg sync.WaitGroup
				n := (len(b) + tc.workers - 1) / tc.workers
				for w := range tc.workers {
					chunk := b[w*n : min((w+1)*n, len(b))]
					wg.Go(func() {
						for i := range chunk {
							sl := &chunk[i]
							sl.inner, sl.o, sl.err = q.Open(sl.pkt)
						}
					})
				}
				return &wg
			}
			var bufs [2][batch]slot
			build(bufs[0][:], 0)
			wg := open(bufs[0][:])
			for r := range rounds {
				wg.Wait()
				cur := bufs[r%2][:]
				if r+1 < rounds {
					build(bufs[(r+1)%2][:], r+1)
					wg = open(bufs[(r+1)%2][:])
				}
				for i := range cur {
					sl := &cur[i]
					err := sl.err
					if err == nil {
						err = q.Accept(sl.o)
					}
					if !errors.Is(err, sl.want) {
						t.Fatalf("round %d packet %d: got %v, want %v", r, i, err, sl.want)
					}
					if err == nil && (binary.BigEndian.Uint32(sl.inner[20:]) != sl.id || sl.o.VNI != testSA().VNI) {
						t.Fatalf("round %d packet %d: got inner %x VNI %#x", r, i, sl.inner, sl.o.VNI)
					}
				}
			}
			for i, spi := range spis {
				if got, _ := tab.Stats(spi); got != want[i] {
					t.Fatalf("SA %d: stats %+v, want %+v", i, got, want[i])
				}
			}
			if st := q.Stats(); st != (QueueStats{}) {
				t.Fatalf("queue stats %+v", st)
			}
		})
	}
}

// TestAccept checks changes to the SA between Open and Accept on queue 0.
func TestAccept(t *testing.T) {
	inner := ipPacket(src4, 60)
	open := func(t *testing.T, q *RxQueue, pkt []byte) Opened {
		t.Helper()
		_, o, err := q.Open(pkt)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	cases := []struct {
		name   string
		queues int
		lane   int
		// run opens packets on queue 0 and changes the table. Accept then
		// gets the packets in order.
		run   func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened
		want  []error
		stats QueueStats
	}{
		{"deleted", 1, 0, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			o := open(t, tab.Queue(0), s.seal(t, 1, inner, nil))
			tab.Delete(spi)
			return []Opened{o}
		}, []error{ErrUnknownSA}, QueueStats{NoMatch: 1}},
		{"row used again", 1, 0, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			o := open(t, tab.Queue(0), s.seal(t, 1, inner, nil))
			tab.Delete(spi)
			add(t, tab, testSA())
			return []Opened{o}
		}, []error{ErrUnknownSA}, QueueStats{NoMatch: 1}},
		{"expired", 1, 0, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			o := open(t, tab.Queue(0), s.seal(t, 1, inner, nil))
			tab.Expire(time.Now().Add(DefaultLifetime))
			return []Opened{o}
		}, []error{ErrUnknownSA}, QueueStats{NoMatch: 1}},
		{"other queue claims first", 2, AnyQueue, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			o := open(t, tab.Queue(0), s.seal(t, 1, inner, nil))
			if _, _, err := tab.Queue(1).Receive(s.seal(t, 2, inner, nil)); err != nil {
				t.Fatal(err)
			}
			return []Opened{o}
		}, []error{ErrHandoffDrop}, QueueStats{HandoffDrops: 1}},
		{"two packets before the claim", 2, AnyQueue, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			q := tab.Queue(0)
			return []Opened{open(t, q, s.seal(t, 1, inner, nil)), open(t, q, s.seal(t, 2, inner, nil))}
		}, []error{nil, nil}, QueueStats{}},
		{"same seq twice", 1, 0, func(t *testing.T, tab *RxTable, spi uint32, s *sender) []Opened {
			q := tab.Queue(0)
			return []Opened{open(t, q, s.seal(t, 5, inner, nil)), open(t, q, s.seal(t, 5, inner, nil))}
		}, []error{nil, ErrReplay}, QueueStats{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab, err := NewRxTable(RxConfig{RowBits: 1, Queues: tc.queues}) // One row.
			if err != nil {
				t.Fatal(err)
			}
			spi, s := addLane(t, tab, tc.lane)
			q := tab.Queue(0)
			for i, o := range tc.run(t, tab, spi, s) {
				if err := q.Accept(o); !errors.Is(err, tc.want[i]) {
					t.Fatalf("packet %d: got %v, want %v", i, err, tc.want[i])
				}
			}
			if st := q.Stats(); st != tc.stats {
				t.Fatalf("queue stats %+v, want %+v", st, tc.stats)
			}
		})
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
