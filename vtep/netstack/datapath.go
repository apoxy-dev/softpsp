// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

// Package netstack is the netstack VTEP driver. It connects a gVisor
// channel.Endpoint to the engine, and sends and receives the frames on an
// underlay that the consumer gives.
//
// The driver does not own the gVisor stack or the underlay. apoxy gives the
// endpoint of its netstack and a binding underlay. clrk gives the NIC of the
// sentry netstack and its own UDP underlay.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/vtep"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/cpu"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// maxBatchSize is the most frames in one underlay write.
const maxBatchSize = 64

// defaultFlushInterval is how often the send pump sends the frames of the
// engine, for example keep-alives, when the endpoint sends nothing.
const defaultFlushInterval = 100 * time.Millisecond

// Underlay sends and receives the frames of the engine. The consumer owns it.
// When the consumer closes it, ReadFrame must return an error that is
// net.ErrClosed, so that Run can return.
type Underlay interface {
	// ReadFrame reads one frame into buf and returns its length. The driver
	// skips a length of 0 with a nil error.
	ReadFrame(buf []byte) (int, error)
	// WriteFrames sends frames and returns the number that it sent. It can
	// send fewer frames than it gets. Then the driver calls it again with the
	// rest, so it must not drop them. Zero with a nil error is a stall. It
	// must not keep the frames after it returns.
	WriteFrames(frames [][]byte) (int, error)
}

// Keeper is an Underlay that can keep the frames of a write after the write
// returns, and send them on other goroutines with no copy. The send pipe
// writes to a Keeper with WriteKept only.
type Keeper interface {
	// WriteKept is WriteFrames for frames that the underlay can keep. Before
	// it returns, it calls k.Keep one time for each group of frames that it
	// keeps. It calls k.Release after it sent or dropped a group.
	WriteKept(frames [][]byte, k *Kept) (int, error)
}

// Kept counts the users of the frames of one write. The frames do not change
// while they have a user.
type Kept struct {
	users atomic.Int32
	free  func() // Runs when the last user releases the frames.
}

// NewKept returns a Kept with no user. It calls free each time the last user
// releases the frames.
func NewKept(free func()) *Kept { return &Kept{free: free} }

// Keep adds a user of the frames. Only a user or the write can call it.
func (k *Kept) Keep() { k.users.Add(1) }

// Release removes a user. Each Keep needs one Release, on any goroutine.
func (k *Kept) Release() {
	if k.users.Add(-1) == 0 {
		k.free()
	}
}

// Config configures a Datapath. Engine, Endpoint and Underlay are required.
type Config struct {
	// Engine encrypts and decrypts the frames. It must run in layer 3 mode.
	Engine vtep.EngineXfrm
	// Endpoint is the gVisor link endpoint. The consumer owns its stack and
	// NIC. The endpoint can have GSO for TCP.
	Endpoint *channel.Endpoint
	// Underlay sends and receives the frames.
	Underlay Underlay
	// FlushInterval is how often the engine frames go out. Zero means
	// defaultFlushInterval.
	FlushInterval time.Duration
}

// Datapath connects a channel.Endpoint to the engine and the underlay. It
// implements vtep.Datapath.
type Datapath struct {
	engine   vtep.EngineXfrm
	ep       *channel.Endpoint
	underlay Underlay
	flush    time.Duration

	// wake has one token when the endpoint has packets. It never closes,
	// because WriteNotify can run at any time, also after Close.
	wake chan struct{}
	// done closes when Close stops the send pump.
	done chan struct{}
	// notifyHandle is the write notification of the endpoint. Close removes
	// it, because the endpoint can live longer than the datapath.
	notifyHandle *channel.NotificationHandle

	// running refuses a second Run.
	running atomic.Bool

	pktPool   sync.Pool
	closeOnce sync.Once

	// pipe seals the frames on other goroutines and sends them in order. Nil
	// when the send pump seals and sends the frames itself.
	pipe *txPipe

	// Send state. Only the send pump uses it, so it has its own cache lines.
	_      cpu.CacheLinePad
	pkt    pktBuf          // One packet of the endpoint.
	hdr    [maxSegHdr]byte // The headers of a TCP packet of the endpoint.
	segs   tcpSegs
	bufs   [maxBatchSize]*[]byte // The pool buffers of the batch.
	frames [maxBatchSize][]byte  // The frames of the batch.
	nf     int                   // The number of frames in the batch.
}

// pktBuf holds one packet of the endpoint. It is the io.Writer of ReadTo.
type pktBuf struct{ b []byte }

func (p *pktBuf) Write(b []byte) (int, error) {
	p.b = append(p.b, b...)
	return len(b), nil
}

// take copies the headers and the payload of pkt into p and returns the
// packet. ToView would clear a 64 KiB chunk for each packet.
func (p *pktBuf) take(pkt *stack.PacketBuffer) []byte {
	p.b = append(p.b[:0], pkt.LinkHeader().Slice()...)
	p.b = append(p.b, pkt.NetworkHeader().Slice()...)
	p.b = append(p.b, pkt.TransportHeader().Slice()...)
	_, _ = pkt.Data().ReadTo(p, true)
	return p.b
}

var _ vtep.Datapath = (*Datapath)(nil)

// New makes a Datapath and adds it to the write notifications of the
// endpoint. Run starts the pumps.
func New(cfg Config) (*Datapath, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("netstack datapath: engine is required")
	}
	if cfg.Endpoint == nil {
		return nil, fmt.Errorf("netstack datapath: endpoint is required")
	}
	if cfg.Underlay == nil {
		return nil, fmt.Errorf("netstack datapath: underlay is required")
	}
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = defaultFlushInterval
	}
	d := &Datapath{
		engine:   cfg.Engine,
		ep:       cfg.Endpoint,
		underlay: cfg.Underlay,
		flush:    flush,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		pkt:      pktBuf{b: make([]byte, 0, 1<<16)},
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 65535)
				return &b
			},
		},
	}
	if eng, ok := cfg.Engine.(Sealer); ok {
		if w := sealWorkers(runtime.GOMAXPROCS(0)); w > 0 {
			d.pipe = newTxPipe(d, eng, w)
		}
	}
	d.notifyHandle = d.ep.AddNotify(d)
	return d, nil
}

// WriteNotify wakes the send pump. The endpoint calls it after a write. It
// is safe to call at the same time as Close.
func (d *Datapath) WriteNotify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Close stops the send pump and removes the write notification. It does not
// close the stack or the underlay of the consumer. The receive pump stops
// when the consumer closes the underlay.
func (d *Datapath) Close() error {
	d.closeOnce.Do(func() {
		if d.notifyHandle != nil {
			d.ep.RemoveNotify(d.notifyHandle)
		}
		close(d.done)
	})
	return nil
}

// Run runs the send and receive pumps until both stop. ctx or Close stops
// the send pump. The receive pump stops only when the consumer closes the
// underlay. A nil error is a clean stop. Run must not be called again.
func (d *Datapath) Run(ctx context.Context) error {
	if !d.running.CompareAndSwap(false, true) {
		return fmt.Errorf("netstack datapath: Run already called")
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		_ = d.Close()
		return nil
	})

	g.Go(d.outbound)
	g.Go(d.inbound)
	if d.pipe != nil {
		g.Go(d.pipe.run)
		for range d.pipe.workers {
			g.Go(d.pipe.seal)
		}
	}

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("netstack datapath splicing failed: %w", err)
	}
	return nil
}

// outbound is the send pump. It sends the packets of the endpoint and the
// frames of the engine until Close. With a pipe, it only reads the packets,
// and the pipe cuts them, seals and sends the frames.
func (d *Datapath) outbound() error {
	ticker := time.NewTicker(d.flush)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return net.ErrClosed
		case <-d.wake:
		case <-ticker.C:
		}
		if err := d.sendQueued(); err != nil {
			return err
		}
	}
}

// sendQueued sends all packets in the queue of the endpoint, then the frames
// of the engine, in batches. It returns an error only when the send pump must
// stop.
func (d *Datapath) sendQueued() error {
	for {
		pkt := d.ep.Read()
		if pkt == nil {
			break
		}
		err := d.addPkt(pkt)
		pkt.DecRef()
		if err != nil {
			return err
		}
	}
	if d.pipe != nil {
		if err := d.pipe.toPhy(); err != nil {
			return err
		}
		d.pipe.flush()
		return nil
	}
	for {
		if d.nf == maxBatchSize {
			if err := d.send(); err != nil {
				return err
			}
		}
		b := d.slot()
		n := d.engine.ToPhy(b)
		if n == 0 {
			break
		}
		d.frames[d.nf] = b[:n]
		d.nf++
	}
	return d.send()
}

// addPkt adds the frames of the packet pkt of the endpoint to the batch, or
// to the pipe. The pipe takes a TCP packet with GSO whole when it can.
func (d *Datapath) addPkt(pkt *stack.PacketBuffer) error {
	gso := pkt.GSOOptions
	if d.pipe != nil && gso.Type != stack.GSONone {
		if ok, err := d.addSegs(pkt, int(gso.MSS)); ok || err != nil {
			return err
		}
	}
	ipLen := len(pkt.NetworkHeader().Slice())
	return d.addPacket(d.pkt.take(pkt), gso, ipLen)
}

// addSegs gives the TCP packet pkt to the pipe, and a seal worker cuts it. It
// returns false when the pump must cut pkt.
func (d *Datapath) addSegs(pkt *stack.PacketBuffer, mss int) (bool, error) {
	ip, tcp := pkt.NetworkHeader().Slice(), pkt.TransportHeader().Slice()
	// A seal worker needs the IP and TCP headers apart from the payload.
	if len(ip)+len(tcp) > maxSegHdr || len(pkt.LinkHeader().Slice()) > 0 {
		return false, nil
	}
	hdr := append(append(d.hdr[:0], ip...), tcp...)
	if !d.segs.init(hdr, len(ip), len(hdr)+pkt.Data().Size(), mss) || d.segs.hdrLen != len(hdr) {
		return false, nil
	}
	return d.pipe.addSegs(pkt, hdr, &d.segs)
}

// addPacket adds the frames of the IP packet pkt to the batch, or to the
// pipe. A TCP packet with GSO becomes one packet for each MSS of payload.
func (d *Datapath) addPacket(pkt []byte, gso stack.GSO, ipLen int) error {
	if gso.Type == stack.GSONone {
		return d.add(pkt)
	}
	if !d.segs.init(pkt, ipLen, len(pkt), int(gso.MSS)) {
		return nil
	}
	for seg := d.segs.next(pkt); seg != nil; seg = d.segs.next(pkt) {
		// The engine gets whole packets: it can keep one that it drops.
		tcpChecksum(seg, ipLen)
		if err := d.add(seg); err != nil {
			return err
		}
	}
	return nil
}

// add adds the frame of the IP packet virt to the batch, or to the pipe. It
// sends the batch first when it is full.
func (d *Datapath) add(virt []byte) error {
	if d.pipe != nil {
		return d.pipe.add(virt)
	}
	if d.nf == maxBatchSize {
		if err := d.send(); err != nil {
			return err
		}
	}
	b := d.slot()
	// The engine runs in layer 3, so it makes no local reply.
	n, _ := d.engine.VirtToPhy(virt, b)
	if n > 0 {
		d.frames[d.nf] = b[:n]
		d.nf++
	}
	return nil
}

// slot returns the buffer for the next frame of the batch.
func (d *Datapath) slot() []byte {
	b := d.bufs[d.nf]
	if b == nil {
		b = d.pktPool.Get().(*[]byte)
		d.bufs[d.nf] = b
	}
	return (*b)[:cap(*b)]
}

// send writes the batch to the underlay and empties it. It returns an error
// only when the underlay or the datapath closes.
func (d *Datapath) send() error {
	err := d.write(d.frames[:d.nf], nil)
	for i, b := range d.bufs {
		if b != nil {
			d.pktPool.Put(b)
			d.bufs[i] = nil
		}
		d.frames[i] = nil
	}
	d.nf = 0
	if err != nil {
		return err
	}
	select {
	case <-d.done:
		return net.ErrClosed
	default:
		return nil
	}
}

// write writes frames to the underlay. It sends again the frames that a short
// write did not send. It logs a failed write, and returns an error only when
// the underlay closes. With k, the underlay of the pipe can keep the frames.
func (d *Datapath) write(frames [][]byte, k *Kept) error {
	out := frames
	for len(out) > 0 {
		var n int
		var err error
		if k != nil {
			n, err = d.pipe.keeper.WriteKept(out, k)
		} else {
			n, err = d.underlay.WriteFrames(out)
		}
		if n > 0 {
			out = out[n:]
		}
		if err == nil && n == 0 {
			err = fmt.Errorf("netstack datapath: underlay write stalled, %d frames undelivered", len(out))
		}
		if err == nil {
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		slog.Warn("Error writing batched underlay frames", slog.Any("error", err))
		return nil
	}
	return nil
}

// inbound reads frames from the underlay, decrypts them and gives the IP
// packets to the endpoint.
func (d *Datapath) inbound() error {
	for {
		phyFrame := d.pktPool.Get().(*[]byte)
		*phyFrame = (*phyFrame)[:cap(*phyFrame)]

		n, err := d.underlay.ReadFrame(*phyFrame)
		if err != nil {
			d.pktPool.Put(phyFrame)
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			slog.Warn("Error reading frame from underlay", slog.Any("error", err))
			continue
		}
		if n == 0 {
			d.pktPool.Put(phyFrame)
			continue
		}

		virtFrame := d.pktPool.Get().(*[]byte)
		*virtFrame = (*virtFrame)[:cap(*virtFrame)]

		vn := d.engine.PhyToVirt((*phyFrame)[:n], *virtFrame)
		d.pktPool.Put(phyFrame)

		if vn == 0 {
			d.pktPool.Put(virtFrame)
			continue
		}

		payload := (*virtFrame)[:vn]
		switch payload[0] >> 4 {
		case header.IPv4Version:
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			pkb.DecRef()
		case header.IPv6Version:
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			pkb.DecRef()
		default:
			// Drop a packet that is not IPv4 or IPv6.
		}
		d.pktPool.Put(virtFrame)
	}
}
