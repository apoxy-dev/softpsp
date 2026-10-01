// SPDX-License-Identifier: AGPL-3.0-only

package keys

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/psp"
)

const (
	testVNI = 0x42
	testMTU = 1280
	life    = engine.DefaultLifetime
)

var t0 = time.Unix(1_000_000, 0)

func newReceiver(tb testing.TB, rowBits int, v psp.Version) (*Receiver, *engine.RxTable) {
	tb.Helper()
	tab, err := engine.NewRxTable(engine.RxConfig{RowBits: rowBits, Queues: MaxLanes})
	if err != nil {
		tb.Fatal(err)
	}
	r, err := NewReceiver(tab, v)
	if err != nil {
		tb.Fatal(err)
	}
	return r, tab
}

// testRoutes routes the source of inner to the test peer.
var testRoutes = func() *engine.Routes[string] {
	r := new(engine.Routes[string])
	if err := r.Add(netip.MustParsePrefix("10.1.0.0/24"), "test"); err != nil {
		panic(err)
	}
	return r
}()

func newPeer(tb testing.TB, r *Receiver, lanes int) *Peer {
	tb.Helper()
	p, err := r.NewPeer(PeerConfig{
		VNI:     testVNI,
		MTU:     testMTU,
		Lanes:   lanes,
		Sources: testRoutes.Sources("test"),
	})
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

func newSender(tb testing.TB) *Sender {
	tb.Helper()
	s, err := NewSender(testMTU)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// offer runs Offer and applies the request at the sender.
func offer(tb testing.TB, p *Peer, tp *TxPeer, now time.Time) Request {
	tb.Helper()
	req, err := p.Offer(now)
	if err != nil {
		tb.Fatal(err)
	}
	apply(tb, tp, req, now)
	return req
}

func apply(tb testing.TB, tp *TxPeer, req Request, now time.Time) {
	tb.Helper()
	if refused, err := tp.Apply(req, now); err != nil || len(refused) != 0 {
		tb.Fatalf("Apply: refused %x, %v", refused, err)
	}
}

// tick runs Tick and wants n updates.
func tick(tb testing.TB, r *Receiver, now time.Time, n int) []Update {
	tb.Helper()
	ups, err := r.Tick(now)
	if err != nil || len(ups) != n {
		tb.Fatalf("Tick at %v: %d updates, %v, want %d", now.Sub(t0), len(ups), err, n)
	}
	return ups
}

var inner = func() []byte {
	p := make([]byte, 60)
	p[0] = 0x45
	copy(p[12:16], []byte{10, 1, 0, 5})
	return p
}()

func seal(tb testing.TB, tx *engine.TxSA) []byte {
	tb.Helper()
	if tx == nil {
		tb.Fatal("no transmit SA")
	}
	pkt := make([]byte, len(inner)+psp.Overhead)
	if _, err := tx.Seal(pkt, inner); err != nil {
		tb.Fatal(err)
	}
	return pkt
}

// sealSeq seals a packet for sa with the sequence number seq.
func sealSeq(tb testing.TB, sa SA, seq uint32) []byte {
	tb.Helper()
	aead, err := psp.NewAEAD(sa.Key)
	if err != nil {
		tb.Fatal(err)
	}
	h := psp.Header{SPI: sa.SPI, IV: uint64(seq), VNI: sa.VNI, Flags: psp.FlagSeq, Seq: seq}
	pkt := make([]byte, len(inner)+psp.Overhead)
	if _, err := psp.Seal(aead, h, pkt, inner); err != nil {
		tb.Fatal(err)
	}
	return pkt
}

// receive wants the queue of lane to accept pkt, or to drop it with want.
func receive(tb testing.TB, tab *engine.RxTable, lane int, pkt []byte, want error) {
	tb.Helper()
	got, vni, err := tab.Queue(lane).Receive(bytes.Clone(pkt))
	if !errors.Is(err, want) {
		tb.Fatalf("Receive: got %v, want %v", err, want)
	}
	if err == nil && (!bytes.Equal(got, inner) || vni != testVNI) {
		tb.Fatalf("Receive: inner %x VNI %#x", got, vni)
	}
}

func TestOffer(t *testing.T) {
	cases := []struct {
		lanes int
		v     psp.Version
	}{{1, psp.AESGCM128}, {4, psp.AESGCM256}, {MaxLanes, psp.AESGCM128}}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d lanes v%d", tc.lanes, tc.v), func(t *testing.T) {
			r, tab := newReceiver(t, 8, tc.v)
			p := newPeer(t, r, tc.lanes)
			tp := newSender(t).NewPeer()
			req := offer(t, p, tp, t0)
			if req.Op != OpOffer || len(req.SAs) != tc.lanes {
				t.Fatalf("got op %d with %d SAs, want an offer of %d", req.Op, len(req.SAs), tc.lanes)
			}
			seen := map[uint32]bool{}
			for i, sa := range req.SAs {
				key, _ := psp.DeriveSAKey(r.masters[0], sa.SPI, tc.v)
				if sa.Lane != i || sa.VNI != testVNI || sa.ExpiresIn != life || !bytes.Equal(sa.Key, key) ||
					psp.MasterKeyIndex(sa.SPI) != 0 || seen[sa.SPI] {
					t.Fatalf("SA %d: %+v", i, sa)
				}
				seen[sa.SPI] = true
				receive(t, tab, i, seal(t, tp.SA(i)), nil)
			}
			if r.live != [2]int{tc.lanes, 0} {
				t.Fatalf("live SAs %v", r.live)
			}
		})
	}
}

func TestRekeyTime(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 2)
	tp := newSender(t).NewPeer()
	first := offer(t, p, tp, t0)
	old1, old2 := seal(t, tp.SA(0)), seal(t, tp.SA(0))

	tick(t, r, t0.Add(life/2), 0)
	ups := tick(t, r, t0.Add(life*3/4), 1)
	if u := ups[0]; u.Peer != p || u.Op != OpRekey || len(u.SAs) != 2 || u.SAs[0].SPI == first.SAs[0].SPI {
		t.Fatalf("update %+v", u)
	}
	apply(t, tp, ups[0].Request, t0.Add(life*3/4))
	if tp.SA(0).SPI() != ups[0].SAs[0].SPI || tp.SA(1).SPI() != ups[0].SAs[1].SPI {
		t.Fatal("the sender did not change to the new SAs")
	}
	receive(t, tab, 0, seal(t, tp.SA(0)), nil)
	receive(t, tab, 1, seal(t, tp.SA(1)), nil)
	receive(t, tab, 0, old1, nil) // The old SA stays for the overlap.

	tick(t, r, t0.Add(life-1), 0)
	receive(t, tab, 0, old2, nil)
	tick(t, r, t0.Add(life), 0)
	receive(t, tab, 0, old2, engine.ErrUnknownSA)
	if r.live != [2]int{2, 0} {
		t.Fatalf("live SAs %v", r.live)
	}
}

func TestRekeyPacketLimit(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 2)
	req := offer(t, p, newSender(t).NewPeer(), t0)
	limit := psp.PacketLimit(testMTU)
	at := limit - limit/4

	receive(t, tab, 1, sealSeq(t, req.SAs[1], at-1), nil)
	tick(t, r, t0.Add(time.Second), 0)
	receive(t, tab, 1, sealSeq(t, req.SAs[1], at), nil)
	ups := tick(t, r, t0.Add(time.Second), 1)
	if len(ups[0].SAs) != 1 || ups[0].SAs[0].Lane != 1 {
		t.Fatalf("got %+v, want a rekey of lane 1", ups[0].SAs)
	}
	receive(t, tab, 1, sealSeq(t, req.SAs[1], at+1), nil) // The overlap.
}

// TestRekeyFull checks that a rekey that does not fit changes nothing, and that
// the next Tick tries again.
func TestRekeyFull(t *testing.T) {
	r, tab := newReceiver(t, 2, psp.AESGCM128) // Rows 1 to 3.
	p := newPeer(t, r, 2)
	tp := newSender(t).NewPeer()
	offer(t, p, tp, t0)
	pkt := seal(t, tp.SA(0))

	if ups, err := r.Tick(t0.Add(life * 3 / 4)); !errors.Is(err, engine.ErrFull) || len(ups) != 0 {
		t.Fatalf("Tick: %d updates, %v, want %v", len(ups), err, engine.ErrFull)
	}
	receive(t, tab, 0, pkt, nil)
	if r.live != [2]int{2, 0} || len(p.old) != 0 {
		t.Fatalf("live SAs %v, %d old", r.live, len(p.old))
	}
	ups := tick(t, r, t0.Add(life), 1) // The SAs expired, so the rows are free.
	apply(t, tp, ups[0].Request, t0.Add(life))
	receive(t, tab, 1, seal(t, tp.SA(1)), nil)
}

func TestRevoke(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 2)
	s := newSender(t)
	tp := s.NewPeer()
	offer(t, p, tp, t0)
	old := seal(t, tp.SA(0))
	ups := tick(t, r, t0.Add(life*3/4), 1)
	apply(t, tp, ups[0].Request, t0.Add(life*3/4))
	cur := seal(t, tp.SA(1))

	req := p.Revoke()
	if req.Op != OpRevoke || len(req.SPIs) != 4 {
		t.Fatalf("got %+v, want a revoke of 4 SPIs", req)
	}
	apply(t, tp, req, t0.Add(life*3/4))
	if tp.SA(0) != nil || tp.SA(1) != nil || len(s.spis) != 0 {
		t.Fatal("the sender still has SAs")
	}
	receive(t, tab, 0, old, engine.ErrUnknownSA)
	receive(t, tab, 1, cur, engine.ErrUnknownSA)
	if r.live != [2]int{} || len(r.peers) != 0 {
		t.Fatalf("live SAs %v, %d peers", r.live, len(r.peers))
	}
	tick(t, r, t0.Add(life), 0)

	offer(t, p, tp, t0.Add(life))
	receive(t, tab, 0, seal(t, tp.SA(0)), nil)
}

func TestClose(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 1)
	s := newSender(t)
	tp := s.NewPeer()
	offer(t, p, tp, t0)
	p.Close()
	tick(t, r, t0.Add(life*3/4), 0)
	receive(t, tab, 0, seal(t, tp.SA(0)), nil)
	if n := s.Expire(t0.Add(life - 1)); n != 0 {
		t.Fatalf("Expire removed %d SAs before the lifetime", n)
	}

	pkt := seal(t, tp.SA(0))
	tick(t, r, t0.Add(life), 0)
	receive(t, tab, 0, pkt, engine.ErrUnknownSA)
	if r.live != [2]int{} || len(r.peers) != 0 {
		t.Fatalf("live SAs %v, %d peers", r.live, len(r.peers))
	}
	if n := s.Expire(t0.Add(life)); n != 1 || tp.SA(0) != nil {
		t.Fatalf("Expire removed %d SAs, want 1", n)
	}
}

func TestRotate(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	s := newSender(t)
	pa, ta := newPeer(t, r, 1), s.NewPeer()
	pb, tb := newPeer(t, r, 1), s.NewPeer()
	offer(t, pa, ta, t0)
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if r.cur != 1 || r.masters[0] != nil {
		t.Fatalf("after Rotate: master %d, old master %x", r.cur, r.masters[0])
	}
	req := offer(t, pb, tb, t0)
	key, _ := psp.DeriveSAKey(r.masters[1], req.SAs[0].SPI, psp.AESGCM128)
	if psp.MasterKeyIndex(req.SAs[0].SPI) != 1 || !bytes.Equal(req.SAs[0].Key, key) {
		t.Fatalf("SA %+v does not use master key 1", req.SAs[0])
	}
	receive(t, tab, 0, seal(t, ta.SA(0)), nil) // The old master key's SA stays.
	receive(t, tab, 0, seal(t, tb.SA(0)), nil)
	if err := r.Rotate(); !errors.Is(err, ErrBusy) {
		t.Fatalf("Rotate with live SAs of master key 0: got %v, want %v", err, ErrBusy)
	}

	for _, u := range tick(t, r, t0.Add(life*3/4), 2) {
		if psp.MasterKeyIndex(u.SAs[0].SPI) != 1 {
			t.Fatalf("rekey SA %#x does not use master key 1", u.SAs[0].SPI)
		}
	}
	if err := r.Rotate(); !errors.Is(err, ErrBusy) {
		t.Fatalf("Rotate in the overlap: got %v, want %v", err, ErrBusy)
	}
	tick(t, r, t0.Add(life), 0)
	if err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if req := offer(t, pa, ta, t0.Add(life)); psp.MasterKeyIndex(req.SAs[0].SPI) != 0 {
		t.Fatalf("SA %#x does not use master key 0", req.SAs[0].SPI)
	}
	receive(t, tab, 0, seal(t, ta.SA(0)), nil)
}

func TestRefused(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 2)
	s := newSender(t)
	tp1, tp2 := s.NewPeer(), s.NewPeer()
	req := offer(t, p, tp1, t0)

	// Another receiver gives tp2 the SPI of lane 0, and a new SPI for lane 1.
	other := req.SAs[1]
	other.SPI ^= 0x100
	refused, err := tp2.Apply(Request{Op: OpOffer, SAs: []SA{req.SAs[0], other}}, t0)
	if err != nil || len(refused) != 1 || refused[0] != req.SAs[0].SPI {
		t.Fatalf("Apply: refused %x, %v, want %x", refused, err, req.SAs[0].SPI)
	}
	if tp2.SA(0) != nil || tp2.SA(1) == nil || tp1.SA(0).SPI() != req.SAs[0].SPI {
		t.Fatal("the refused SA changed a lane")
	}

	// The receiver gives other SAs for the refused SPIs, at once.
	pkt := sealSeq(t, req.SAs[0], 1)
	again, err := p.Refused([]uint32{req.SAs[0].SPI, 12345}, t0)
	if err != nil || again.Op != OpOffer || len(again.SAs) != 1 || again.SAs[0].Lane != 0 || again.SAs[0].SPI == req.SAs[0].SPI {
		t.Fatalf("Refused: %+v, %v", again, err)
	}
	receive(t, tab, 0, pkt, engine.ErrUnknownSA)
	receive(t, tab, 0, sealSeq(t, again.SAs[0], 1), nil)
	if r.live != [2]int{2, 0} {
		t.Fatalf("live SAs %v", r.live)
	}
}

func TestApplyErrors(t *testing.T) {
	good := SA{SPI: 0x1234, Key: make([]byte, 16), VNI: 1, ExpiresIn: time.Minute, Lane: 0}
	cases := []struct {
		name string
		edit func(*SA)
		op   Op
	}{
		{"unknown op", nil, 0},
		{"lane 16", func(sa *SA) { sa.Lane = MaxLanes }, OpOffer},
		{"lane -1", func(sa *SA) { sa.Lane = -1 }, OpRekey},
		{"no lifetime", func(sa *SA) { sa.ExpiresIn = 0 }, OpOffer},
		{"key 20 bytes", func(sa *SA) { sa.Key = make([]byte, 20) }, OpOffer},
		{"VNI too big", func(sa *SA) { sa.VNI = psp.MaxVNI + 1 }, OpOffer},
		{"reserved SPI", func(sa *SA) { sa.SPI = 0 }, OpOffer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			bad.SPI, bad.Lane = 0x5678, 1
			if tc.edit != nil {
				tc.edit(&bad)
			}
			tp := newSender(t).NewPeer()
			if _, err := tp.Apply(Request{Op: tc.op, SAs: []SA{good, bad}}, t0); err == nil {
				t.Fatal("Apply accepted the request")
			}
			if tp.SA(0) != nil {
				t.Fatal("Apply used the good SA of a bad request")
			}
		})
	}
}

func TestConfigErrors(t *testing.T) {
	tab, _ := engine.NewRxTable(engine.RxConfig{RowBits: 4})
	if _, err := NewReceiver(tab, 2); err == nil {
		t.Error("NewReceiver accepted version 2")
	}
	sources := testRoutes.Sources("test")
	one, _ := NewReceiver(tab, psp.AESGCM128)
	if _, err := one.NewPeer(PeerConfig{VNI: 1, MTU: testMTU, Lanes: 2, Sources: sources}); err == nil {
		t.Error("NewPeer accepted 2 lanes on a table with 1 queue")
	}
	r, _ := newReceiver(t, 4, psp.AESGCM128)
	for _, lanes := range []int{0, MaxLanes + 1} {
		if _, err := r.NewPeer(PeerConfig{VNI: 1, MTU: testMTU, Lanes: lanes, Sources: sources}); err == nil {
			t.Errorf("NewPeer accepted %d lanes", lanes)
		}
	}
	if _, err := r.NewPeer(PeerConfig{VNI: 1, MTU: testMTU, Lanes: 1}); err == nil {
		t.Error("NewPeer accepted no source check")
	}
	p, _ := r.NewPeer(PeerConfig{VNI: psp.MaxVNI + 1, MTU: testMTU, Lanes: 2, Sources: sources})
	if _, err := p.Offer(t0); err == nil || r.live != [2]int{} || len(r.peers) != 0 {
		t.Errorf("Offer with a bad VNI: %v, live SAs %v", err, r.live)
	}
	if _, err := NewSender(0); err == nil {
		t.Error("NewSender accepted MTU 0")
	}
}

// TestRoutes sends each packet with the SAs of the peer that the route of its
// destination gives.
func TestRoutes(t *testing.T) {
	s := newSender(t)
	var routes engine.Routes[*TxPeer]
	var tabs []*engine.RxTable
	for _, p := range []string{"10.2.0.0/16", "fd00:2::/64"} {
		r, tab := newReceiver(t, 8, psp.AESGCM128)
		tp := s.NewPeer()
		offer(t, newPeer(t, r, 2), tp, t0)
		if err := routes.Add(netip.MustParsePrefix(p), tp); err != nil {
			t.Fatal(err)
		}
		tabs = append(tabs, tab)
	}
	cases := []struct {
		dst  string
		want int // Index of the receiver, or -1 for no route.
	}{{"10.2.3.4", 0}, {"fd00:2::9", 1}, {"10.3.0.1", -1}, {"fd00:3::1", -1}}
	for _, tc := range cases {
		tp, ok := routes.Lookup(netip.MustParseAddr(tc.dst))
		if ok != (tc.want >= 0) {
			t.Fatalf("Lookup(%s): found %v", tc.dst, ok)
		}
		if !ok {
			continue
		}
		for lane := range 2 {
			pkt := seal(t, tp.SA(lane))
			receive(t, tabs[tc.want], lane, pkt, nil)
			if _, _, err := tabs[1-tc.want].Queue(lane).Receive(bytes.Clone(pkt)); err == nil {
				t.Fatalf("%s: the other receiver accepted the packet", tc.dst)
			}
		}
	}
}

// TestConcurrent seals and receives on one goroutine while the receiver
// rekeys. Every packet must pass, because the old SA stays for the overlap.
func TestConcurrent(t *testing.T) {
	r, tab := newReceiver(t, 8, psp.AESGCM128)
	p := newPeer(t, r, 2)
	tp := newSender(t).NewPeer()
	offer(t, p, tp, t0)
	stop := make(chan struct{})
	var sent atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		pkt := make([]byte, len(inner)+psp.Overhead)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n, err := tp.SA(i%2).Seal(pkt, inner)
			if err == nil {
				_, _, err = tab.Queue(i % 2).Receive(pkt[:n])
			}
			if err != nil {
				t.Error(err)
				return
			}
			sent.Add(1)
		}
	})
	for i := 1; i <= 20; i++ {
		now := t0.Add(time.Duration(i) * life * 3 / 4)
		for _, u := range tick(t, r, now, 1) {
			apply(t, tp, u.Request, now)
		}
		// Each tick moves the clock 3/4 of the lifetime. Wait until a packet
		// sealed after this rekey is received, so that no packet waits across
		// two ticks and finds its SA expired.
		for n := sent.Load(); sent.Load() < n+2 && !t.Failed(); {
			runtime.Gosched()
		}
	}
	close(stop)
	wg.Wait()
}

// FuzzReceiver runs random key changes on two peers, and after each one
// checks that the receiver and the sender agree and that the counts are right.
func FuzzReceiver(f *testing.F) {
	f.Add([]byte{0x00, 0x10, 0x31, 0x02, 0x01, 0x40, 0x13, 0x05, 0x11, 0x04, 0x51})
	f.Add([]byte{0x00, 0x30, 0x41, 0x31, 0x04, 0x71, 0x21, 0x10, 0x04, 0xf1, 0x04})
	f.Fuzz(func(t *testing.T, ops []byte) {
		r, tab := newReceiver(t, 5, psp.AESGCM128)
		s := newSender(t)
		peers := []*Peer{newPeer(t, r, 3), newPeer(t, r, 1)}
		tps := []*TxPeer{s.NewPeer(), s.NewPeer()}
		now := t0
		send := func(i int, req Request) {
			if _, err := tps[i].Apply(req, now); err != nil {
				t.Fatal(err)
			}
		}
		for _, op := range ops {
			i := int(op>>4) & 1
			p := peers[i]
			switch op & 0xf {
			case 0:
				if req, err := p.Offer(now); err == nil {
					send(i, req)
				}
			case 1:
				now = now.Add(time.Duration(op>>5) * life / 8)
				ups, _ := r.Tick(now)
				for _, u := range ups {
					send(slices.Index(peers, u.Peer), u.Request)
				}
				s.Expire(now)
			case 2:
				send(i, p.Revoke())
			case 3:
				p.Close()
			case 4:
				r.Rotate()
			case 5:
				if sa := p.lanes[int(op>>5)%len(p.lanes)]; sa != nil {
					if req, err := p.Refused([]uint32{sa.spi}, now); err == nil {
						send(i, req)
					}
				}
			}

			var live [2]int
			for i, p := range peers {
				for lane, sa := range p.lanes {
					tx := tps[i].SA(lane)
					if (sa == nil) != (tx == nil) || (sa != nil && sa.spi != tx.SPI()) {
						t.Fatalf("peer %d lane %d: the receiver and the sender do not agree", i, lane)
					}
					if tx != nil {
						receive(t, tab, lane, seal(t, tx), nil)
					}
				}
				for _, sa := range append(p.old, p.lanes...) {
					if sa != nil {
						live[psp.MasterKeyIndex(sa.spi)]++
					}
				}
				if _, ok := r.peers[p]; !ok && !p.empty() {
					t.Fatalf("peer %d has SAs but Tick does not see it", i)
				}
			}
			if live != r.live {
				t.Fatalf("live SAs %v, want %v", r.live, live)
			}
		}
	})
}

func TestApplyRepeatedSPI(t *testing.T) {
	cases := []struct {
		name string
		op   Op
		lane int
	}{
		{"repeated offer", OpOffer, 0},
		{"repeated rekey", OpRekey, 0},
		{"move to another lane", OpOffer, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, tab := newReceiver(t, 8, psp.AESGCM128)
			p := newPeer(t, r, 1)
			tp := newSender(t).NewPeer()
			req := offer(t, p, tp, t0)
			before := tp.SA(0)
			receive(t, tab, 0, seal(t, before), nil)
			req.Op, req.SAs[0].Lane = tc.op, tc.lane
			refused, err := tp.Apply(req, t0.Add(time.Second))
			if err != nil || !slices.Equal(refused, []uint32{req.SAs[0].SPI}) {
				t.Fatalf("Apply = %v, %v; want the held SPI refused", refused, err)
			}
			if tp.SA(0) != before || tp.SA(1) != nil {
				t.Fatal("a repeated SPI changed a transmit SA")
			}
			// The receiver must accept the next sequence number.
			receive(t, tab, 0, seal(t, tp.SA(0)), nil)
		})
	}
}
