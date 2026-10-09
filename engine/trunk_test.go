// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/replay"
)

const (
	// maxRelayRead is the largest UDP payload that a relay socket reads.
	maxRelayRead = 1452
	// trunkMTU is the largest payload of a trunk packet of that size.
	trunkMTU = maxRelayRead - psp.Overhead
)

func trunkSA(noReplay bool) RxSA {
	return RxSA{Master: testMaster, Version: psp.AESGCM128, MTU: trunkMTU, Trunk: true, NoReplay: noReplay}
}

// agentPacket returns the PSP packet of an agent for an n-byte inner packet.
func agentPacket(tb testing.TB, n int) []byte {
	tb.Helper()
	tx := addTx(tb, newTable(tb, 4), testSA())
	pkt := make([]byte, n+psp.Overhead)
	if _, err := tx.Seal(pkt, ipPacket(src4, n)); err != nil {
		tb.Fatal(err)
	}
	return pkt
}

// sealTrunk seals payload on tx with the sequence number seq. A PSP packet
// goes through SealTrunkPSP, an inner IP packet through SealTrunk.
func sealTrunk(tb testing.TB, tx *TxSA, seq, tag uint32, payload []byte, isPSP bool) []byte {
	tb.Helper()
	tx.next.Store(uint64(seq))
	pkt := make([]byte, len(payload)+psp.Overhead)
	seal := tx.SealTrunk
	if isPSP {
		seal = tx.SealTrunkPSP
	}
	if n, err := seal(tag, pkt, payload); err != nil || n != len(pkt) {
		tb.Fatalf("seal: %d, %v, want %d", n, err, len(pkt))
	}
	return pkt
}

// TestTrunk sends each kind of payload on a trunk SA with and without a replay
// window. The receiver gets the same bytes, the tag and the Next Header value.
func TestTrunk(t *testing.T) {
	cases := []struct {
		name     string
		noReplay bool
		payload  []byte
		isPSP    bool
		tag      uint32
		nextHdr  uint8
		want     error
	}{
		{name: "PSP packet, no window", noReplay: true, payload: agentPacket(t, 100), isPSP: true, tag: 1, nextHdr: psp.NextHdrPSP},
		{name: "PSP packet, window", payload: agentPacket(t, 100), isPSP: true, tag: psp.MaxVNI, nextHdr: psp.NextHdrPSP},
		{name: "IPv4 packet, window", payload: ipPacket(src4, 100), tag: 0x00a5c3, nextHdr: psp.NextHdrV4},
		{name: "IPv6 packet, window", payload: ipPacket(src6, 100), tag: 0x00a5c3, nextHdr: psp.NextHdrV6},
		{name: "source that no route allows", payload: ipPacket(netip.MustParseAddr("192.0.2.1"), 100), tag: 7, nextHdr: psp.NextHdrV4},
		{name: "tag 0", noReplay: true, payload: agentPacket(t, 100), isPSP: true, tag: 0, nextHdr: psp.NextHdrPSP},
		{name: "IPv4 packet, no window", noReplay: true, payload: ipPacket(src4, 100), tag: 1, want: ErrPayload},
		{name: "IPv6 packet, no window", noReplay: true, payload: ipPacket(src6, 100), tag: 1, want: ErrPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, trunkSA(tc.noReplay))
			for seq := range uint32(3) {
				pkt := sealTrunk(t, tx, seq, tc.tag, tc.payload, tc.isPSP)
				h, err := psp.ParseTrunkHeader(pkt)
				if err != nil || h.VNI != tc.tag || h.Seq != seq || h.IV != uint64(seq) || h.Flags != psp.FlagSeq {
					t.Fatalf("header %+v, %v: want tag %#x, seq and IV %d, flag S", h, err, tc.tag, seq)
				}
				got, tag, nextHdr, err := tab.Queue(0).ReceiveTrunk(pkt)
				if !errors.Is(err, tc.want) {
					t.Fatalf("ReceiveTrunk %d: got %v, want %v", seq, err, tc.want)
				}
				if err == nil && (!bytes.Equal(got, tc.payload) || tag != tc.tag || nextHdr != tc.nextHdr) {
					t.Fatalf("ReceiveTrunk %d: tag %#x, next header %d, payload %x", seq, tag, nextHdr, got)
				}
			}
			want := RxStats{Packets: 3, Seq: 2}
			if tc.want != nil {
				want = RxStats{Rejects: 3}
			}
			if st, _ := tab.Stats(tx.SPI()); st != want {
				t.Fatalf("stats %+v, want %+v", st, want)
			}
		})
	}
}

// TestTrunkLargest sends the largest payloads that fit a relay socket read.
func TestTrunkLargest(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		isPSP   bool
		size    int // Length of the trunk packet.
	}{
		{"PSP packet at inner MTU 1280", agentPacket(t, 1280), true, 1360},
		{"largest PSP packet", agentPacket(t, trunkMTU-psp.Overhead), true, maxRelayRead},
		{"largest IPv4 packet", ipPacket(src4, trunkMTU), false, maxRelayRead},
		{"largest IPv6 packet", ipPacket(src6, trunkMTU), false, maxRelayRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, trunkSA(false))
			seal := tx.SealTrunk
			if tc.isPSP {
				seal = tx.SealTrunkPSP
			}
			if _, err := seal(1, make([]byte, tc.size-1), tc.payload); !errors.Is(err, psp.ErrBuffer) {
				t.Fatalf("seal to %d bytes: got %v, want %v", tc.size-1, err, psp.ErrBuffer)
			}
			pkt := make([]byte, tc.size)
			if n, err := seal(1, pkt, tc.payload); err != nil || n != tc.size {
				t.Fatalf("seal: %d, %v, want %d", n, err, tc.size)
			}
			got, _, _, err := tab.Queue(0).ReceiveTrunk(pkt)
			if err != nil || !bytes.Equal(got, tc.payload) {
				t.Fatalf("ReceiveTrunk: %v, %d bytes, want %d", err, len(got), len(tc.payload))
			}
		})
	}
}

// TestTrunkTag changes the tag of a sealed packet. The ICV covers the tag, so
// each change fails, and the packet with its own tag still passes.
func TestTrunkTag(t *testing.T) {
	const tag = 0x00a5c3
	type change struct {
		name string
		edit func(vni []byte)
	}
	changes := []change{
		{"tag 0", func(vni []byte) { copy(vni, []byte{0, 0, 0}) }},
		{"next tag", func(vni []byte) { vni[2]++ }},
		{"largest tag", func(vni []byte) { copy(vni, []byte{0xff, 0xff, 0xff}) }},
	}
	for bit := range 24 {
		changes = append(changes, change{fmt.Sprintf("bit %d", bit), func(vni []byte) { vni[bit/8] ^= 0x80 >> (bit % 8) }})
	}
	for _, noReplay := range []bool{true, false} {
		t.Run(fmt.Sprintf("no window %v", noReplay), func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, trunkSA(noReplay))
			payload := agentPacket(t, 100)
			pkt := sealTrunk(t, tx, 4, tag, payload, true)
			for _, c := range changes {
				forged := bytes.Clone(pkt)
				c.edit(forged[psp.HeaderLen : psp.HeaderLen+3])
				if h, err := psp.ParseTrunkHeader(forged); err != nil || h.VNI == tag {
					t.Fatalf("%s: header %+v, %v: want another tag", c.name, h, err)
				}
				if _, _, _, err := tab.Queue(0).ReceiveTrunk(forged); !errors.Is(err, psp.ErrAuth) {
					t.Fatalf("%s: got %v, want %v", c.name, err, psp.ErrAuth)
				}
			}
			got, gotTag, _, err := tab.Queue(0).ReceiveTrunk(pkt)
			if err != nil || gotTag != tag || !bytes.Equal(got, payload) {
				t.Fatalf("packet with its own tag: tag %#x, %v", gotTag, err)
			}
			want := RxStats{Packets: 1, ICVFailures: uint64(len(changes)), Seq: 4}
			if st, _ := tab.Stats(tx.SPI()); st != want {
				t.Fatalf("stats %+v, want %+v", st, want)
			}
		})
	}
}

// TestTrunkReplay sends copies and old packets. An SA with no replay window
// passes them all, and an SA with a window drops them.
func TestTrunkReplay(t *testing.T) {
	type step struct {
		seq  uint32
		want error
	}
	const w = replay.WindowSize
	cases := []struct {
		name     string
		noReplay bool
		isPSP    bool
		steps    []step
		want     RxStats
	}{
		{name: "no window", noReplay: true, isPSP: true, steps: []step{
			{seq: 5}, {seq: 5}, {seq: 3}, {seq: 3}, {seq: w + 10}, {seq: 5}, {seq: 6},
		}, want: RxStats{Packets: 7, Seq: w + 10}},
		{name: "window, PSP packet", isPSP: true, steps: []step{
			{seq: 5}, {seq: 5, want: ErrReplay}, {seq: 3}, {seq: 3, want: ErrReplay}, {seq: w + 10}, {seq: 5, want: ErrReplay}, {seq: 10},
		}, want: RxStats{Packets: 4, Replays: 3, Seq: w + 10}},
		{name: "window, IP packet", steps: []step{
			{seq: 5}, {seq: 5, want: ErrReplay}, {seq: 3}, {seq: 3, want: ErrReplay}, {seq: w + 10}, {seq: 5, want: ErrReplay}, {seq: 10},
		}, want: RxStats{Packets: 4, Replays: 3, Seq: w + 10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, trunkSA(tc.noReplay))
			payload := ipPacket(src4, 100)
			if tc.isPSP {
				payload = agentPacket(t, 100)
			}
			for i, st := range tc.steps {
				got, _, _, err := tab.Queue(0).ReceiveTrunk(sealTrunk(t, tx, st.seq, 9, payload, tc.isPSP))
				if !errors.Is(err, st.want) {
					t.Fatalf("step %d (seq %d): got %v, want %v", i, st.seq, err, st.want)
				}
				if err == nil && !bytes.Equal(got, payload) {
					t.Fatalf("step %d: payload %x", i, got)
				}
			}
			if st, _ := tab.Stats(tx.SPI()); st != tc.want {
				t.Fatalf("stats %+v, want %+v", st, tc.want)
			}
		})
	}
}

// TestTrunkForward sends the packet of an agent across a trunk, as two relays
// do. The far relay gets the same bytes, and the receiving agent opens them. A
// copy of the trunk packet passes the far relay, and the agent drops it.
func TestTrunkForward(t *testing.T) {
	const tag = 0x000102
	agent := newTable(t, 4)
	toAgent := addTx(t, agent, testSA())
	far := newTable(t, 4)
	toFar := addTx(t, far, trunkSA(true))

	inner := ipPacket(src4, 1280)
	sent := make([]byte, len(inner)+psp.Overhead)
	if _, err := toAgent.Seal(sent, inner); err != nil {
		t.Fatal(err)
	}
	trunk := make([]byte, len(sent)+psp.Overhead)
	if _, err := toFar.SealTrunkPSP(tag, trunk, sent); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(trunk, sent[:psp.PrefixLen]) {
		t.Fatal("the trunk packet shows the header of the agent packet")
	}

	for i, want := range []error{nil, ErrReplay} {
		got, gotTag, nextHdr, err := far.Queue(0).ReceiveTrunk(bytes.Clone(trunk))
		if err != nil || gotTag != tag || nextHdr != psp.NextHdrPSP || !bytes.Equal(got, sent) {
			t.Fatalf("copy %d at the far relay: tag %#x, next header %d, %v", i, gotTag, nextHdr, err)
		}
		// The far relay finds the row of the agent packet from its SPI.
		if h, err := psp.ParseHeader(got); err != nil || h.SPI != toAgent.SPI() {
			t.Fatalf("copy %d: header of the agent packet %+v, %v", i, h, err)
		}
		open, vni, err := agent.Queue(0).Receive(got)
		if !errors.Is(err, want) {
			t.Fatalf("copy %d at the agent: got %v, want %v", i, err, want)
		}
		if err == nil && (!bytes.Equal(open, inner) || vni != testSA().VNI) {
			t.Fatalf("copy %d at the agent: VNI %#x, inner %x", i, vni, open)
		}
	}
}

// TestTrunkModes checks that an SA accepts only the packets of its kind. A
// plain SA is an SA that is not a trunk SA. It refuses a PSP packet as the
// payload, because that has no inner source to check.
func TestTrunkModes(t *testing.T) {
	vni := testSA().VNI
	receive := func(q *RxQueue, pkt []byte) error {
		_, _, err := q.Receive(pkt)
		return err
	}
	open := func(q *RxQueue, pkt []byte) error {
		_, _, err := q.Open(pkt)
		return err
	}
	receiveTrunk := func(q *RxQueue, pkt []byte) error {
		_, _, _, err := q.ReceiveTrunk(pkt)
		return err
	}
	inner := ipPacket(src4, 100)
	cases := []struct {
		name  string
		sa    RxSA
		tag   uint32
		isPSP bool
		recv  func(q *RxQueue, pkt []byte) error
		want  error
		stats RxStats
		queue QueueStats
	}{
		{name: "plain SA, PSP packet, Receive", sa: testSA(), tag: vni, isPSP: true, recv: receive,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, PSP packet, Open", sa: testSA(), tag: vni, isPSP: true, recv: open,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, PSP packet, ReceiveTrunk", sa: testSA(), tag: vni, isPSP: true, recv: receiveTrunk,
			want: ErrUnknownSA, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, IP packet, ReceiveTrunk", sa: testSA(), tag: vni, recv: receiveTrunk,
			want: ErrUnknownSA, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, IP packet, Receive", sa: testSA(), tag: vni, recv: receive,
			stats: RxStats{Packets: 1}},
		{name: "trunk SA, IP packet, Receive", sa: trunkSA(false), tag: 0, recv: receive,
			want: ErrSource, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, IP packet with a tag, Receive", sa: trunkSA(false), tag: 5, recv: receive,
			want: ErrVNI, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, IP packet, Open", sa: trunkSA(false), tag: 0, recv: open,
			want: ErrSource, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, PSP packet, Receive", sa: trunkSA(false), tag: 0, isPSP: true, recv: receive,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "trunk SA with no window, PSP packet, Receive", sa: trunkSA(true), tag: 0, isPSP: true, recv: receive,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "trunk SA, IP packet, ReceiveTrunk", sa: trunkSA(false), tag: 0, recv: receiveTrunk,
			stats: RxStats{Packets: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, tc.sa)
			payload := inner
			if tc.isPSP {
				payload = agentPacket(t, 100)
			}
			q := tab.Queue(0)
			if err := tc.recv(q, sealTrunk(t, tx, 0, tc.tag, payload, tc.isPSP)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if st, _ := tab.Stats(tx.SPI()); st != tc.stats {
				t.Fatalf("stats %+v, want %+v", st, tc.stats)
			}
			if st := q.Stats(); st != tc.queue {
				t.Fatalf("queue stats %+v, want %+v", st, tc.queue)
			}
		})
	}
}

// TestTrunkChecks checks flag S and the packet limit on a trunk SA.
func TestTrunkChecks(t *testing.T) {
	limit9000 := psp.PacketLimit(9000)
	cases := []struct {
		name string
		mtu  int
		seq  uint32
		edit func(*psp.Header)
		want error
	}{
		{name: "last sequence number", seq: 1<<31 - 1},
		{name: "limit", seq: 1 << 31, want: ErrLimit},
		{name: "last sequence number at MTU 9000", mtu: 9000, seq: limit9000 - 1},
		{name: "limit at MTU 9000", mtu: 9000, seq: limit9000, want: ErrLimit},
		{name: "flag S clear", seq: 1, edit: func(h *psp.Header) { h.Flags = 0 }, want: ErrNoSeq},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := trunkSA(false)
			if tc.mtu != 0 {
				sa.MTU = tc.mtu
			}
			tab := newTable(t, 4)
			_, s := add(t, tab, sa)
			pkt := s.seal(t, tc.seq, ipPacket(src4, 60), tc.edit)
			if _, _, _, err := tab.Queue(0).ReceiveTrunk(pkt); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSealTrunkErrors(t *testing.T) {
	payload := agentPacket(t, 60)
	cases := []struct {
		name    string
		tag     uint32
		payload []byte
		isPSP   bool
		atLimit bool
		want    error
	}{
		{name: "tag too big, PSP packet", tag: psp.MaxVNI + 1, payload: payload, isPSP: true, want: psp.ErrVNI},
		{name: "tag too big, IP packet", tag: psp.MaxVNI + 1, payload: ipPacket(src4, 60), want: psp.ErrVNI},
		{name: "PSP packet as an IP packet", tag: 1, payload: payload, want: psp.ErrNextHdr},
		{name: "empty IP packet", tag: 1, want: psp.ErrNextHdr},
		{name: "limit, PSP packet", tag: 1, payload: payload, isPSP: true, atLimit: true, want: ErrLimit},
		{name: "limit, IP packet", tag: 1, payload: ipPacket(src4, 60), atLimit: true, want: ErrLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := addTx(t, newTable(t, 4), trunkSA(false))
			if tc.atLimit {
				tx.next.Store(uint64(tx.limit))
			}
			seal := tx.SealTrunk
			if tc.isPSP {
				seal = tx.SealTrunkPSP
			}
			if _, err := seal(tc.tag, make([]byte, len(tc.payload)+psp.Overhead), tc.payload); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTrunkAdd(t *testing.T) {
	tab := newTable(t, 4)
	cases := []struct {
		name string
		edit func(*RxSA)
	}{
		{"trunk SA with a VNI", func(sa *RxSA) { sa.VNI = 1 }},
		{"trunk SA with a source check", func(sa *RxSA) { sa.Sources = testRoutes.Sources("test") }},
		{"plain SA with no window", func(sa *RxSA) { *sa = testSA(); sa.NoReplay = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := trunkSA(true)
			tc.edit(&sa)
			if _, _, err := tab.Add(sa); err == nil {
				t.Fatal("Add accepted the SA")
			}
		})
	}
}

// TestTrunkOwner checks that only the owner queue receives a trunk SA, and
// that a packet on another queue drops with no hand-off.
func TestTrunkOwner(t *testing.T) {
	for _, lane := range []int{1, AnyQueue} {
		t.Run(fmt.Sprintf("lane %d", lane), func(t *testing.T) {
			tab := newQueues(t, 2)
			sa := trunkSA(false)
			sa.Lane = lane
			tx := addTx(t, tab, sa)
			payload := agentPacket(t, 100)
			steps := []struct {
				queue int
				want  error
			}{{1, nil}, {0, ErrHandoffDrop}, {1, nil}}
			for i, st := range steps {
				pkt := sealTrunk(t, tx, uint32(i), 1, payload, true)
				if _, _, _, err := tab.Queue(st.queue).ReceiveTrunk(pkt); !errors.Is(err, st.want) {
					t.Fatalf("step %d: got %v, want %v", i, err, st.want)
				}
			}
			if st := tab.Queue(0).Stats(); st != (QueueStats{HandoffDrops: 1}) {
				t.Fatalf("queue stats %+v", st)
			}
			if n := tab.Queue(1).Drain(func([]byte, uint32) {}); n != 0 {
				t.Fatalf("Drain read %d packets, want 0", n)
			}
			if st, _ := tab.Stats(tx.SPI()); st.Packets != 2 {
				t.Fatalf("stats %+v, want 2 packets", st)
			}
		})
	}
}

func TestTrunkNoAllocs(t *testing.T) {
	tab := newTable(t, 4)
	payload := agentPacket(t, 1280)
	inner := ipPacket(src4, 1280)
	pkt := make([]byte, len(payload)+psp.Overhead)
	buf := make([]byte, len(pkt))
	fwd, bridged := addTx(t, tab, trunkSA(true)), addTx(t, tab, trunkSA(false))
	cases := []struct {
		name string
		fn   func()
	}{
		{"SealTrunk", func() {
			if _, err := bridged.SealTrunk(1, pkt, inner); err != nil {
				t.Fatal(err)
			}
		}},
		{"SealTrunkPSP and ReceiveTrunk", func() {
			if _, err := fwd.SealTrunkPSP(1, buf, payload); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := tab.Queue(0).ReceiveTrunk(buf); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		if a := testing.AllocsPerRun(100, tc.fn); a != 0 {
			t.Errorf("%s: %v allocs per run, want 0", tc.name, a)
		}
	}
}

// BenchmarkTrunk measures a relay that sends the packet of an agent on a trunk
// SA with no replay window, and the relay that receives it. ReceiveTrunk
// decrypts in place, so each loop copies the sealed packet first.
func BenchmarkTrunk(b *testing.B) {
	for _, n := range []int{64, 1280} {
		tab := newTable(b, 4)
		tx := addTx(b, tab, trunkSA(true))
		payload := agentPacket(b, n)
		pkt := sealTrunk(b, tx, 0, 1, payload, true)
		b.Run(fmt.Sprintf("%d/seal", n), func(b *testing.B) {
			dst := make([]byte, len(pkt))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.SealTrunkPSP(1, dst, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/receive", n), func(b *testing.B) {
			buf := make([]byte, len(pkt))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				copy(buf, pkt)
				if _, _, _, err := tab.Queue(0).ReceiveTrunk(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
