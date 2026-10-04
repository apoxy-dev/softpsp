// SPDX-License-Identifier: Apache-2.0

package netstack

import (
	"net"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/vtep"
)

const (
	// txSets is the number of frame sets of a send pipe with no seal workers.
	// Each seal worker adds two sets.
	txSets = 8
	// txSlots is the most frames in one set, and so in one underlay write.
	txSlots = maxBatchSize
	// maxSealWorkers is the most seal workers of a send pipe. One worker seals
	// tens of Gbps, and more workers only take CPUs from the pump and the
	// netstack.
	maxSealWorkers = 2
)

// Sealer is an engine that can seal frames on many goroutines at once. The
// driver uses it in place of VirtToPhy when the host has 4 or more CPUs.
type Sealer interface {
	vtep.EngineXfrm
	// Overhead returns the most bytes that a frame adds to its inner packet.
	Overhead() int
	// Prepare starts the frame of the inner packet virt: it picks the SA and
	// reserves the sequence number. It runs on the send pump, in send order.
	// It returns false to drop the packet.
	Prepare(virt []byte, f *TxFrame) bool
	// Seal writes the frame of virt, from Prepare, to phy and returns its
	// length, or 0 to drop the packet. It can change virt. Many goroutines
	// can run it at once.
	Seal(f *TxFrame, virt, phy []byte) int
}

// TxFrame is the state of one frame between Prepare and Seal.
type TxFrame struct {
	// SA and Seq are the SA and the sequence number of a PSP packet. SA is
	// nil for a frame with no PSP packet.
	SA  *engine.TxSA
	Seq uint64
	// Dst is the address that the frame goes to.
	Dst netip.AddrPort
	// Lane is the send lane of the frame.
	Lane int
}

// sealWorkers returns the number of seal workers of a send pipe for procs
// CPUs. Zero means no pipe.
func sealWorkers(procs int) int {
	if procs < 4 {
		return 0
	}
	return min(procs/4, maxSealWorkers)
}

// txPipe moves the frames of the send pump to seal workers and then to one
// sender, in send order. The pump copies each inner packet into a slot of a
// set and prepares its frame. A seal worker seals the set and gives a token.
// The sender takes the sets in order, waits for the token and writes the
// frames to the underlay.
type txPipe struct {
	d       *Datapath
	eng     Sealer
	mtu     int
	workers int
	cur     *txSet      // The set that the pump fills. Nil until it adds a frame.
	work    chan *txSet // Sets for the seal workers.
	full    chan *txSet // Sets for the sender, in send order.
	free    chan *txSet // Empty sets for the pump.

	mu      sync.Mutex // Guards closing and the sends of flush.
	closing bool       // Set when the sender stops. Then flush drops the sets.
}

type txSet struct {
	slots  []txSlot
	n      int
	frames [][]byte      // The frames of the set, in order. The sealer fills it.
	sealed chan struct{} // Gets one token when a seal worker finished the set.
}

// txSlot is one frame of a set.
type txSlot struct {
	virt []byte // The inner packet.
	phy  []byte // The frame.
	n    int    // The length of the inner packet, or of the frame when seal is false.
	seal bool   // False for a frame of ToPhy, which is complete.
	f    TxFrame
}

// newTxPipe makes a pipe with workers seal workers, at least one.
func newTxPipe(d *Datapath, eng Sealer, workers int) *txPipe {
	sets := txSets + 2*workers
	mtu := int(d.ep.MTU())
	p := &txPipe{d: d, eng: eng, mtu: mtu, workers: workers, work: make(chan *txSet, sets), full: make(chan *txSet, sets), free: make(chan *txSet, sets)}
	size := mtu + eng.Overhead()
	slab := make([]byte, sets*txSlots*(mtu+size))
	for range sets {
		s := &txSet{slots: make([]txSlot, txSlots), frames: make([][]byte, 0, txSlots), sealed: make(chan struct{}, 1)}
		for i := range s.slots {
			s.slots[i].virt, slab = slab[:mtu:mtu], slab[mtu:]
			s.slots[i].phy, slab = slab[:size:size], slab[size:]
		}
		p.free <- s
	}
	return p
}

// slot returns the next free slot of the current set. It waits for a free set
// when the current one is full, and returns net.ErrClosed when the datapath
// closes.
func (p *txPipe) slot() (*txSlot, error) {
	s := p.cur
	if s != nil && s.n == txSlots {
		p.flush()
		s = nil
	}
	if s == nil {
		select {
		case s = <-p.free:
		case <-p.d.done:
			return nil, net.ErrClosed
		}
		p.cur = s
	}
	return &s.slots[s.n], nil
}

// add prepares the frame of the inner packet virt and copies virt into the
// current set.
func (p *txPipe) add(virt []byte) error {
	if len(virt) > p.mtu {
		// The endpoint sends no packet above its MTU.
		return nil
	}
	sl, err := p.slot()
	if err != nil {
		return err
	}
	if !p.eng.Prepare(virt, &sl.f) {
		return nil
	}
	sl.n = copy(sl.virt, virt)
	sl.seal = true
	p.cur.n++
	return nil
}

// toPhy adds the frames of the engine, for example keep-alives, to the
// current set.
func (p *txPipe) toPhy() error {
	for {
		sl, err := p.slot()
		if err != nil {
			return err
		}
		n := p.eng.ToPhy(sl.phy)
		if n == 0 {
			return nil
		}
		sl.n, sl.seal = n, false
		p.cur.n++
	}
}

// flush gives the current set to the seal workers and the sender.
func (p *txPipe) flush() {
	s := p.cur
	if s == nil || s.n == 0 {
		return
	}
	p.cur = nil
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return
	}
	// The channels hold all sets, so these sends do not wait.
	p.work <- s
	p.full <- s
}

// seal is a seal worker. It seals the sets of work in order and gives a token
// for each one, until the sender closes work.
func (p *txPipe) seal() error {
	for s := range p.work {
		if p.stopped() {
			s.frames = s.frames[:0]
		} else {
			p.sealSet(s)
		}
		s.sealed <- struct{}{}
	}
	return nil
}

// sealSet seals the frames of s.
func (p *txPipe) sealSet(s *txSet) {
	s.frames = s.frames[:0]
	for i := range s.slots[:s.n] {
		sl := &s.slots[i]
		n := sl.n
		if sl.seal {
			n = p.eng.Seal(&sl.f, sl.virt[:sl.n], sl.phy)
		}
		if n > 0 {
			s.frames = append(s.frames, sl.phy[:n])
		}
	}
}

// run is the sender. It writes the sets to the underlay in send order until
// the datapath closes or the underlay closes.
func (p *txPipe) run() error {
	for {
		select {
		case s := <-p.full:
			if !p.wait(s) {
				p.stop()
				return net.ErrClosed
			}
			err := p.d.write(s.frames)
			s.frames = s.frames[:0]
			s.n = 0
			p.free <- s
			if err != nil {
				p.stop()
				return err
			}
		case <-p.d.done:
			p.stop()
			return net.ErrClosed
		}
	}
}

// wait waits for the token of s. It returns false when the datapath closes.
func (p *txPipe) wait(s *txSet) bool {
	select {
	case <-s.sealed:
		return true
	case <-p.d.done:
		return false
	}
}

// stop ends the seal workers and makes flush drop the sets.
func (p *txPipe) stop() {
	p.mu.Lock()
	p.closing = true
	close(p.work)
	p.mu.Unlock()
}

func (p *txPipe) stopped() bool {
	select {
	case <-p.d.done:
		return true
	default:
		return false
	}
}
