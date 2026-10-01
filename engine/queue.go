// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/apoxy-dev/softpsp/psp"
)

const (
	inboxSlots   = 256 // Packets that can wait for one queue.
	handoffLimit = 64  // Packets of one SA that can wait for its owner queue.
)

// RxQueue is one receive queue. Only one goroutine at a time can use it.
type RxQueue struct {
	t     *RxTable
	id    int32
	inbox inbox
	spare [][]byte // The inbox buffers that Drain reads.

	nomatch, handoffs, handoffDrops atomic.Uint64
}

// inbox holds the packets that other queues give to the owner queue. It has
// two sets of buffers: other queues fill one while the owner reads the other.
type inbox struct {
	waiting atomic.Int32 // Packets in bufs, so that Drain can skip the lock.

	mu   sync.Mutex
	gen  uint64 // Increments at each Drain. It resets the limit of each SA.
	n    int
	bufs [][]byte
}

// QueueStats are the counters of one receive queue.
type QueueStats struct {
	NoMatch      uint64 // Packets with a bad header or no SA.
	Handoffs     uint64 // Packets sent to the owner queue of their SA.
	HandoffDrops uint64 // Packets dropped at the hand-off.
}

func newRxQueue(t *RxTable, id int) *RxQueue {
	q := &RxQueue{t: t, id: int32(id), spare: make([][]byte, inboxSlots)}
	q.inbox.bufs = make([][]byte, inboxSlots)
	return q
}

// Stats returns the counters of the queue.
func (q *RxQueue) Stats() QueueStats {
	return QueueStats{
		NoMatch:      q.nomatch.Load(),
		Handoffs:     q.handoffs.Load(),
		HandoffDrops: q.handoffDrops.Load(),
	}
}

// Receive checks and decrypts the PSP packet pkt in place. It returns the
// inner packet, which is in pkt, and the VNI. If another queue owns the SA, it
// copies pkt to that queue and returns ErrHandoff.
func (q *RxQueue) Receive(pkt []byte) ([]byte, uint32, error) {
	h, err := psp.ParseHeader(pkt)
	if err != nil {
		q.nomatch.Add(1)
		return nil, 0, err
	}
	row := q.t.rows[h.SPI&q.t.rowMask].Load()
	if row == nil || row.spi != h.SPI || row.version != h.Version {
		q.nomatch.Add(1)
		return nil, 0, ErrUnknownSA
	}
	owner := row.owner.Load()
	if owner != q.id && owner != AnyQueue {
		return nil, 0, q.handoff(row, owner, pkt)
	}
	inner, err := psp.OpenInPlace(row.aead, pkt)
	if errors.Is(err, psp.ErrAuth) {
		row.icvFailures.Add(1)
		return nil, 0, err
	}
	if err == nil {
		err = row.check(&h, inner)
	}
	if err != nil {
		row.rejects.Add(1)
		return nil, 0, err
	}
	// Another queue can claim the SA after the Load above. Its packet came
	// first, so this one drops.
	if owner == AnyQueue && !row.owner.CompareAndSwap(AnyQueue, q.id) {
		q.handoffDrops.Add(1)
		return nil, 0, ErrHandoffDrop
	}
	if !row.window.Check(h.Seq) {
		row.replays.Add(1)
		return nil, 0, ErrReplay
	}
	row.seq.Store(row.window.Last())
	row.packets.Add(1)
	return inner, h.VNI, nil
}

// Drain receives the packets that other queues gave to q, and calls deliver
// for each inner packet that passes. The inner packet is valid only during the
// call. Call Drain in each poll loop of q. It returns how many packets it read.
func (q *RxQueue) Drain(deliver func(inner []byte, vni uint32)) int {
	ib := &q.inbox
	if ib.waiting.Load() == 0 {
		return 0
	}
	ib.mu.Lock()
	n := ib.n
	ib.bufs, q.spare = q.spare, ib.bufs
	ib.n = 0
	ib.gen++
	ib.waiting.Store(0)
	ib.mu.Unlock()
	for _, pkt := range q.spare[:n] {
		if inner, vni, err := q.Receive(pkt); err == nil {
			deliver(inner, vni)
		}
	}
	return n
}

// handoff copies pkt to the inbox of the owner queue. Each SA can have at most
// handoffLimit packets in one inbox between two Drains. Packets longer than
// the SA MTU drop, so that inbox buffers stay small.
func (q *RxQueue) handoff(row *rxRow, owner int32, pkt []byte) error {
	if len(pkt) > row.maxLen {
		q.handoffDrops.Add(1)
		return ErrHandoffDrop
	}
	ib := &q.t.queues[owner].inbox
	ib.mu.Lock()
	if row.handoffGen != ib.gen {
		row.handoffGen, row.handoffs = ib.gen, 0
	}
	if row.handoffs >= handoffLimit || ib.n == len(ib.bufs) {
		ib.mu.Unlock()
		q.handoffDrops.Add(1)
		return ErrHandoffDrop
	}
	row.handoffs++
	ib.bufs[ib.n] = append(ib.bufs[ib.n][:0], pkt...)
	ib.n++
	ib.waiting.Store(int32(ib.n))
	ib.mu.Unlock()
	q.handoffs.Add(1)
	return ErrHandoff
}
