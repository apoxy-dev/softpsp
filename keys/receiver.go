// SPDX-License-Identifier: AGPL-3.0-only

package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
	"github.com/apoxy-dev/softpsp/psp"
)

// Receiver creates the SAs of one RxTable. It keeps two master keys, and bit 31
// of each SPI selects one.
//
// An SA is rekeyed after 3/4 of its lifetime or 3/4 of its packet limit. The
// SA that a rekey replaces stays for at most 1/4 of the lifetime.
type Receiver struct {
	table    *engine.RxTable
	version  psp.Version
	lifetime time.Duration

	mu      sync.Mutex
	masters [psp.NumMasterKeys][]byte
	cur     int                    // Master key of new SAs.
	live    [psp.NumMasterKeys]int // Live SAs of each master key.
	peers   map[*Peer]struct{}     // Open peers, and closed peers with SAs.
}

// PeerConfig is the receive policy for the SAs of one sender.
type PeerConfig struct {
	VNI uint32
	MTU int // Inner MTU. It sets the packet limit.
	// Lanes is the number of SAs, 1 to MaxLanes. Queue i modulo the queue
	// count of the table owns lane i. With one lane, the queue of the first
	// packet owns the SA.
	Lanes int
	// Sources is the source check of the SAs, for example Routes.Sources.
	Sources func(netip.Addr) bool
	// Trunk makes trunk SAs (engine.RxSA.Trunk), for the packets from another
	// relay. They have no VNI and no Sources.
	Trunk bool
	// NoReplayLanes is the number of trunk lanes, from lane 0, whose SAs have
	// no replay window (engine.RxSA.NoReplay).
	NoReplayLanes int
}

// Peer is one sender of a Receiver.
type Peer struct {
	r      *Receiver
	cfg    PeerConfig
	lanes  []*rxSA // Current SA of each lane, or nil.
	old    []*rxSA // SAs that a rekey replaced.
	closed bool    // No rekeys.
}

type rxSA struct {
	spi      uint32
	lane     int
	rekeyAt  time.Time
	rekeySeq uint32
	expires  time.Time
}

// Update is a Request that Tick made for one peer.
type Update struct {
	Peer *Peer
	Request
}

// NewReceiver returns a Receiver with a new master key. Its SAs use version v.
func NewReceiver(t *engine.RxTable, v psp.Version) (*Receiver, error) {
	if !v.Valid() {
		return nil, psp.ErrVersion
	}
	m, err := newMaster()
	if err != nil {
		return nil, err
	}
	r := &Receiver{table: t, version: v, lifetime: t.Lifetime(), peers: map[*Peer]struct{}{}}
	r.masters[0] = m
	return r, nil
}

// Rotate puts a new master key in the other slot and uses it for new SAs. The
// SAs of the old master key stay until a rekey replaces them or they expire.
func (r *Receiver) Rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	next := 1 - r.cur
	if r.live[next] > 0 {
		return ErrBusy
	}
	m, err := newMaster()
	if err != nil {
		return err
	}
	// The rows keep their AEAD, so the old master key is not necessary again.
	clear(r.masters[r.cur])
	r.masters[r.cur], r.masters[next], r.cur = nil, m, next
	return nil
}

// NewPeer returns a peer with no SAs.
func (r *Receiver) NewPeer(cfg PeerConfig) (*Peer, error) {
	switch {
	case cfg.Lanes < 1 || cfg.Lanes > MaxLanes:
		return nil, fmt.Errorf("keys: lanes must be 1 to %d, got %d", MaxLanes, cfg.Lanes)
	case cfg.Trunk && (cfg.VNI != 0 || cfg.Sources != nil):
		return nil, errors.New("keys: a trunk peer has no VNI and no source check")
	case !cfg.Trunk && cfg.Sources == nil:
		return nil, errors.New("keys: no source check")
	case !cfg.Trunk && cfg.NoReplayLanes != 0:
		return nil, errors.New("keys: only a trunk peer can have lanes with no replay window")
	case cfg.NoReplayLanes < 0 || cfg.NoReplayLanes > cfg.Lanes:
		return nil, fmt.Errorf("keys: lanes with no replay window must be 0 to %d, got %d", cfg.Lanes, cfg.NoReplayLanes)
	}
	return &Peer{r: r, cfg: cfg, lanes: make([]*rxSA, cfg.Lanes)}, nil
}

// Tick deletes the SAs whose time ended, and rekeys the SAs of open peers that
// are due. The caller sends each Update to its sender. Call it about once a
// second. It returns the first error, and the failed lanes are due again at
// the next Tick.
func (r *Receiver) Tick(now time.Time) ([]Update, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ups []Update
	var first error
	for p := range r.peers {
		p.expire(now)
		if p.closed {
			if p.empty() {
				delete(r.peers, p)
			}
			continue
		}
		var due []int
		for i, sa := range p.lanes {
			if sa == nil || !now.Before(sa.rekeyAt) || r.seq(sa) >= sa.rekeySeq {
				due = append(due, i)
			}
		}
		if len(due) == 0 {
			continue
		}
		sas, err := p.replace(due, now)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		ups = append(ups, Update{Peer: p, Request: Request{Op: OpRekey, SAs: sas}})
	}
	return ups, first
}

// Offer creates a new SA for each lane and opens the peer for rekeys. SAs from
// an earlier offer stay for the overlap.
func (p *Peer) Offer(now time.Time) (Request, error) {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	lanes := make([]int, len(p.lanes))
	for i := range lanes {
		lanes[i] = i
	}
	sas, err := p.replace(lanes, now)
	if err != nil {
		return Request{}, err
	}
	p.closed = false
	p.r.peers[p] = struct{}{}
	return Request{Op: OpOffer, SAs: sas}, nil
}

// Refused deletes the SAs that the sender refused and offers new SAs for their
// lanes. It ignores SPIs that are not current SAs of the peer.
func (p *Peer) Refused(spis []uint32, now time.Time) (Request, error) {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	var lanes []int
	for i, sa := range p.lanes {
		if sa != nil && slices.Contains(spis, sa.spi) {
			p.r.delete(sa) // The sender did not use it, so no overlap.
			p.lanes[i] = nil
			lanes = append(lanes, i)
		}
	}
	sas, err := p.replace(lanes, now)
	if err != nil {
		return Request{}, err
	}
	return Request{Op: OpOffer, SAs: sas}, nil
}

// Revoke deletes all SAs of the peer and returns the request for the sender.
// A later Offer gives the peer new SAs.
func (p *Peer) Revoke() Request {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	var spis []uint32
	for i, sa := range p.lanes {
		if sa != nil {
			spis = append(spis, sa.spi)
			p.r.delete(sa)
			p.lanes[i] = nil
		}
	}
	for _, sa := range p.old {
		spis = append(spis, sa.spi)
		p.r.delete(sa)
	}
	p.old = nil
	delete(p.r.peers, p)
	return Request{Op: OpRevoke, SPIs: spis}
}

// Close stops rekeys for the peer, for example when its session closes. Its
// SAs stay until they expire.
func (p *Peer) Close() {
	p.r.mu.Lock()
	defer p.r.mu.Unlock()
	p.closed = true
}

// replace creates a new SA for each lane. The SAs that they replace stay for
// at most 1/4 of the lifetime. If one create fails, it deletes the new SAs and
// changes nothing. r.mu must be held.
func (p *Peer) replace(lanes []int, now time.Time) ([]SA, error) {
	r := p.r
	sas := make([]SA, 0, len(lanes))
	made := make([]*rxSA, 0, len(lanes))
	for _, lane := range lanes {
		owner := lane % r.table.Queues()
		if len(p.lanes) == 1 {
			owner = engine.AnyQueue
		}
		spi, key, err := r.table.Add(engine.RxSA{
			Master:      r.masters[r.cur],
			MasterIndex: r.cur,
			Version:     r.version,
			VNI:         p.cfg.VNI,
			Sources:     p.cfg.Sources,
			MTU:         p.cfg.MTU,
			Lane:        owner,
			Trunk:       p.cfg.Trunk,
			NoReplay:    lane < p.cfg.NoReplayLanes,
		})
		if err != nil {
			for _, sa := range made {
				r.delete(sa)
			}
			return nil, err
		}
		r.live[r.cur]++
		limit := psp.PacketLimit(p.cfg.MTU)
		made = append(made, &rxSA{
			spi:      spi,
			lane:     lane,
			rekeyAt:  now.Add(r.lifetime * 3 / 4),
			rekeySeq: limit - limit/4,
			expires:  now.Add(r.lifetime),
		})
		sas = append(sas, SA{SPI: spi, Key: key, VNI: p.cfg.VNI, ExpiresIn: r.lifetime, Lane: lane})
	}
	end := now.Add(r.lifetime / 4)
	for _, sa := range made {
		if prev := p.lanes[sa.lane]; prev != nil {
			if end.Before(prev.expires) {
				prev.expires = end
			}
			p.old = append(p.old, prev)
		}
		p.lanes[sa.lane] = sa
	}
	return sas, nil
}

// expire deletes the SAs whose time ended. r.mu must be held.
func (p *Peer) expire(now time.Time) {
	ended := func(sa *rxSA) bool {
		if sa == nil || now.Before(sa.expires) {
			return false
		}
		p.r.delete(sa)
		return true
	}
	for i, sa := range p.lanes {
		if ended(sa) {
			p.lanes[i] = nil
		}
	}
	p.old = slices.DeleteFunc(p.old, ended)
}

func (p *Peer) empty() bool {
	return len(p.old) == 0 && !slices.ContainsFunc(p.lanes, func(sa *rxSA) bool { return sa != nil })
}

// delete removes the receive row of sa. r.mu must be held.
func (r *Receiver) delete(sa *rxSA) {
	r.table.Delete(sa.spi)
	r.live[psp.MasterKeyIndex(sa.spi)]--
}

// seq returns the highest sequence number that the SA accepted.
func (r *Receiver) seq(sa *rxSA) uint32 {
	st, _ := r.table.Stats(sa.spi)
	return st.Seq
}

func newMaster() ([]byte, error) {
	m := make([]byte, psp.MasterKeyLen)
	if _, err := rand.Read(m); err != nil {
		return nil, err
	}
	return m, nil
}
