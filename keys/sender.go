// SPDX-License-Identifier: AGPL-3.0-only

package keys

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
)

// Sender holds the transmit SAs that receivers gave to this process. The SPI
// of each SA is unique in the Sender, because relays find the next hop of a
// packet from its sender and SPI.
type Sender struct {
	mtu int

	mu   sync.Mutex
	spis map[uint32]holder // The lane that holds each SPI.
}

type holder struct {
	p    *TxPeer
	lane int
}

// TxPeer holds the transmit SAs from one receiver, one for each lane.
type TxPeer struct {
	s       *Sender
	lanes   [MaxLanes]atomic.Pointer[engine.TxSA]
	expires [MaxLanes]time.Time // Guarded by s.mu.
}

// NewSender returns a Sender. The inner MTU sets the packet limit of its SAs.
func NewSender(mtu int) (*Sender, error) {
	if mtu <= 0 {
		return nil, fmt.Errorf("keys: MTU must be positive, got %d", mtu)
	}
	return &Sender{mtu: mtu, spis: map[uint32]holder{}}, nil
}

// NewPeer returns a TxPeer with no SAs.
func (s *Sender) NewPeer() *TxPeer { return &TxPeer{s: s} }

// Expire removes the SAs whose lifetime ended, and returns how many it removed.
func (s *Sender) Expire(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for spi, l := range s.spis {
		if !now.Before(l.p.expires[l.lane]) {
			l.p.lanes[l.lane].Store(nil)
			delete(s.spis, spi)
			n++
		}
	}
	return n
}

// SA returns the transmit SA of the lane, or nil.
func (p *TxPeer) SA(lane int) *engine.TxSA { return p.lanes[lane].Load() }

// Apply applies a request from the receiver at now, the time of receipt. It
// returns the SPIs that the sender already holds, including for this peer.
func (p *TxPeer) Apply(req Request, now time.Time) ([]uint32, error) {
	s := p.s
	switch req.Op {
	case OpOffer, OpRekey:
		txs := make([]*engine.TxSA, len(req.SAs))
		for i, sa := range req.SAs {
			if sa.Lane < 0 || sa.Lane >= MaxLanes || sa.ExpiresIn <= 0 {
				return nil, fmt.Errorf("keys: SA %#x has lane %d and lifetime %v", sa.SPI, sa.Lane, sa.ExpiresIn)
			}
			tx, err := engine.NewTxSA(sa.SPI, sa.Key, sa.VNI, s.mtu)
			if err != nil {
				return nil, err
			}
			txs[i] = tx
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		var refused []uint32
		for i, sa := range req.SAs {
			if _, ok := s.spis[sa.SPI]; ok {
				// Replacing a held SA would reuse its key and nonce from zero.
				refused = append(refused, sa.SPI)
				continue
			}
			if prev := p.lanes[sa.Lane].Load(); prev != nil {
				delete(s.spis, prev.SPI())
			}
			s.spis[sa.SPI] = holder{p, sa.Lane}
			p.lanes[sa.Lane].Store(txs[i])
			p.expires[sa.Lane] = now.Add(sa.ExpiresIn)
		}
		return refused, nil
	case OpRevoke:
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, spi := range req.SPIs {
			if l, ok := s.spis[spi]; ok && l.p == p {
				p.lanes[l.lane].Store(nil)
				delete(s.spis, spi)
			}
		}
		return nil, nil
	}
	return nil, fmt.Errorf("keys: unknown op %d", req.Op)
}
