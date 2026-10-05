// SPDX-License-Identifier: Apache-2.0

package netstack

import (
	"net"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/vtep"
	"golang.org/x/sys/cpu"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// txSets is the number of frame sets of a send pipe with no seal workers.
	// Each seal worker adds two sets.
	txSets = 8
	// txKeepSets is the number of sets that a pipe adds for a Keeper: the sets
	// whose frames wait in the underlay.
	txKeepSets = 16
	// txSlots is the most frames in one set, and so in one underlay write.
	txSlots = maxBatchSize
	// maxSealWorkers is the most seal workers of a send pipe. A worker also
	// cuts the TCP packets and completes the TCP checksums.
	maxSealWorkers = 4
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
	// PrepareSegs is Prepare for the n packets of one TCP packet with the
	// headers hdr: size is the largest one, total is all bytes, and packet i
	// gets f.Seq+i. On false it did nothing: the pump prepares each packet.
	PrepareSegs(hdr []byte, n, size, total int, f *TxFrame) bool
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
// sender, in send order. The pump gives each TCP packet of the endpoint to a
// set as a run, and copies each other packet into a slot. A seal worker cuts
// the runs, seals the set and gives a token. The sender takes the sets in
// order, waits for the token and writes the frames to the underlay. A Keeper
// sends the frames from the set, and the set is free after the last Release.
type txPipe struct {
	d       *Datapath
	eng     Sealer
	keeper  Keeper // The underlay when it can keep frames. Nil when it copies them.
	mtu     int
	workers int
	work    chan *txSet // Sets for the seal workers.
	full    chan *txSet // Sets for the sender, in send order.
	free    chan *txSet // Empty sets for the pump.

	// The pump writes the fields below. The pads keep them off the cache
	// lines that the seal workers and the sender read.
	_       cpu.CacheLinePad
	cur     *txSet     // The set that the pump fills. Nil until it adds a frame.
	f       TxFrame    // The frame of PrepareSegs. A local would be on the heap.
	mu      sync.Mutex // Guards closing and the sends of flush.
	closing bool       // Set when the sender stops. Then flush drops the sets.
	_       cpu.CacheLinePad
}

// txSet is the frames of one underlay write. One goroutine owns it at a time:
// the pump, then a seal worker, then the sender. After the write, a Keeper can
// read the frames until the last Release of kept.
type txSet struct {
	_      cpu.CacheLinePad // Two sets do not have a cache line in common.
	slots  []txSlot
	n      int           // Slots in use.
	runs   []txRun       // The TCP packets that a seal worker cuts, in slot order.
	frames [][]byte      // The frames of the set, in order. The sealer fills it.
	sealed chan struct{} // Gets one token when a seal worker finished the set.
	kept   Kept          // The users of frames in a write to a Keeper.
}

// txSlot is one frame of a set.
type txSlot struct {
	virt []byte // The inner packet.
	phy  []byte // The frame.
	n    int    // The length of the inner packet, or of the frame when seal is false.
	seal bool   // False for a frame of ToPhy, which is complete.
	f    TxFrame
}

// txRun is the packets of one TCP packet of the endpoint that are in one set.
// The pump does not copy them: a seal worker cuts them from pkt into slots.
type txRun struct {
	pkt  *stack.PacketBuffer // The run owns one reference.
	segs tcpSegs             // The cut, at the first packet of the run.
	slot int                 // The first slot.
	n    int                 // The number of packets, one slot for each.
	f    TxFrame             // The frame of the first packet.
}

// reset empties s after a seal worker cut its runs.
func (s *txSet) reset() { s.runs, s.frames, s.n = s.runs[:0], s.frames[:0], 0 }

// drop empties s with no seal. It releases the packets of the runs.
func (s *txSet) drop() {
	for i := range s.runs {
		s.runs[i].pkt.DecRef()
		s.runs[i].pkt = nil
	}
	s.reset()
}

// newTxPipe makes a pipe with workers seal workers, at least one.
func newTxPipe(d *Datapath, eng Sealer, workers int) *txPipe {
	sets := txSets + 2*workers
	keeper, _ := d.underlay.(Keeper)
	if keeper != nil {
		sets += txKeepSets
	}
	mtu := int(d.ep.MTU())
	p := &txPipe{d: d, eng: eng, keeper: keeper, mtu: mtu, workers: workers, work: make(chan *txSet, sets), full: make(chan *txSet, sets), free: make(chan *txSet, sets)}
	size := mtu + eng.Overhead()
	slab := make([]byte, sets*txSlots*(mtu+size))
	all := make([]txSet, sets)
	for i := range all {
		s := &all[i]
		s.slots, s.runs = make([]txSlot, txSlots), make([]txRun, 0, txSlots)
		s.frames, s.sealed = make([][]byte, 0, txSlots), make(chan struct{}, 1)
		for i := range s.slots {
			s.slots[i].virt, slab = slab[:mtu:mtu], slab[mtu:]
			s.slots[i].phy, slab = slab[:size:size], slab[size:]
		}
		s.kept.free = func() { p.release(s) }
		p.free <- s
	}
	return p
}

// set returns the current set, which has a free slot. It waits for a free set
// when the current one is full, and returns net.ErrClosed when the datapath
// closes.
func (p *txPipe) set() (*txSet, error) {
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
	return s, nil
}

// add prepares the frame of the inner packet virt and copies virt into the
// current set.
func (p *txPipe) add(virt []byte) error {
	if len(virt) > p.mtu {
		// The endpoint sends no packet above its MTU.
		return nil
	}
	s, err := p.set()
	if err != nil {
		return err
	}
	sl := &s.slots[s.n]
	if !p.eng.Prepare(virt, &sl.f) {
		return nil
	}
	sl.n = copy(sl.virt, virt)
	sl.seal = true
	s.n++
	return nil
}

// addSegs prepares the frames of the TCP packet pkt in one call and gives pkt
// to the sets as runs, with no copy. On false, the pump must cut pkt.
func (p *txPipe) addSegs(pkt *stack.PacketBuffer, hdr []byte, segs *tcpSegs) (bool, error) {
	size := segs.hdrLen + segs.length()
	if size > p.mtu {
		return false, nil
	}
	n := segs.count()
	if !p.eng.PrepareSegs(hdr, n, size, segs.size+(n-1)*segs.hdrLen, &p.f) {
		return false, nil
	}
	for i := 0; i < n; {
		s, err := p.set()
		if err != nil {
			return true, err
		}
		k := min(n-i, txSlots-s.n)
		s.runs = s.runs[:len(s.runs)+1]
		r := &s.runs[len(s.runs)-1]
		r.pkt, r.segs, r.slot, r.n, r.f = pkt.IncRef(), *segs, s.n, k, p.f
		r.segs.seek(i)
		r.f.Seq += uint64(i)
		s.n += k
		i += k
	}
	return true, nil
}

// toPhy adds the frames of the engine, for example keep-alives, to the
// current set.
func (p *txPipe) toPhy() error {
	for {
		s, err := p.set()
		if err != nil {
			return err
		}
		sl := &s.slots[s.n]
		n := p.eng.ToPhy(sl.phy)
		if n == 0 {
			return nil
		}
		sl.n, sl.seal = n, false
		s.n++
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
		s.drop()
		return
	}
	// The channels hold all sets, so these sends do not wait.
	p.work <- s
	p.full <- s
}

// seal is a seal worker. It seals the sets of work in order and gives a token
// for each one, until the sender closes work.
func (p *txPipe) seal() error {
	c := &segCut{p: p}
	for s := range p.work {
		if p.stopped() {
			s.drop()
		} else {
			p.sealSet(s, c)
		}
		s.sealed <- struct{}{}
	}
	return nil
}

// sealSet cuts the runs of s with c and seals the frames of s, in slot order.
func (p *txPipe) sealSet(s *txSet, c *segCut) {
	s.frames = s.frames[:0]
	runs := s.runs
	for i := 0; i < s.n; {
		if len(runs) > 0 && runs[0].slot == i {
			c.cut(s, &runs[0])
			i += runs[0].n
			runs = runs[1:]
			continue
		}
		sl := &s.slots[i]
		n := sl.n
		if sl.seal {
			n = p.eng.Seal(&sl.f, sl.virt[:sl.n], sl.phy)
		}
		if n > 0 {
			s.frames = append(s.frames, sl.phy[:n])
		}
		i++
	}
}

// segCut cuts the packets of a run into their slots and seals them. It is the
// writer that gets the payload of the TCP packet. Each seal worker has one.
type segCut struct {
	p    *txPipe
	s    *txSet
	segs *tcpSegs
	f    TxFrame // The frame of the next packet.
	slot int     // The slot of the next packet.
	end  int     // The slot after the last packet of the run.
	skip int     // Payload bytes before the next packet.
	n    int     // The payload length of the next packet.
	fill int     // The payload bytes of the next packet that are in its slot.
}

// cut cuts and seals the packets of the run r of s, and releases its packet.
func (c *segCut) cut(s *txSet, r *txRun) {
	c.s, c.segs, c.f = s, &r.segs, r.f
	c.slot, c.end = r.slot, r.slot+r.n
	c.skip = r.segs.off - r.segs.hdrLen
	c.n, c.fill = r.segs.length(), 0
	if c.n == 0 {
		// A packet with no payload gets no Write.
		c.seal()
	} else {
		_, _ = r.pkt.Data().ReadTo(c, true)
	}
	r.pkt.DecRef()
	r.pkt = nil
}

// Write copies the payload b into the slots of the run. It seals each packet
// that has all its payload.
func (c *segCut) Write(b []byte) (int, error) {
	n := len(b)
	if c.skip > 0 {
		k := min(c.skip, len(b))
		c.skip -= k
		b = b[k:]
	}
	for len(b) > 0 && c.slot < c.end {
		off := c.segs.hdrLen + c.fill
		k := copy(c.s.slots[c.slot].virt[off:off+c.n-c.fill], b)
		b = b[k:]
		c.fill += k
		if c.fill == c.n {
			c.seal()
		}
	}
	return n, nil
}

// seal writes the headers of the next packet before its payload, completes
// its TCP checksum and seals it.
func (c *segCut) seal() {
	sl := &c.s.slots[c.slot]
	virt := sl.virt[:c.segs.hdrLen+c.n]
	c.segs.header(virt)
	tcpChecksum(virt, c.segs.ipLen)
	if n := c.p.eng.Seal(&c.f, virt, sl.phy); n > 0 {
		c.s.frames = append(c.s.frames, sl.phy[:n])
	}
	c.f.Seq++
	c.slot++
	c.n, c.fill = c.segs.length(), 0
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
			if err := p.write(s); err != nil {
				p.stop()
				return err
			}
		case <-p.d.done:
			p.stop()
			return net.ErrClosed
		}
	}
}

// write writes the frames of s to the underlay and frees s. The sender is a
// user of the frames in a write to a Keeper, so s is free only after the write.
func (p *txPipe) write(s *txSet) error {
	if p.keeper == nil {
		err := p.d.write(s.frames, nil)
		p.release(s)
		return err
	}
	s.kept.Keep()
	err := p.d.write(s.frames, &s.kept)
	s.kept.Release()
	return err
}

// release gives s, whose frames have no user, to the pump. The channel holds
// all sets, so the send does not wait, also after the pipe stopped.
func (p *txPipe) release(s *txSet) {
	s.reset()
	p.free <- s
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
