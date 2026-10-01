// SPDX-License-Identifier: AGPL-3.0-only

// Package engine is the SoftPSP packet engine.
//
// The receive side keeps one row for each receive SA. The SPI selects the row
// directly. After the packet decrypts, the row checks flag S, the VNI, the
// packet limit, the inner source and the replay window.
//
// Each row has one owner queue, and only that queue writes the replay window
// and the counters of the row. A packet that arrives on another queue goes to
// the owner queue through a hand-off with a limit for each SA.
package engine

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/softpsp/psp"
	"github.com/apoxy-dev/softpsp/replay"
)

const (
	DefaultRowBits  = 16
	DefaultLifetime = 10 * time.Minute
	MaxQueues       = 16 // The largest number of receive queues.
	// AnyQueue as RxSA.Lane makes the queue of the first packet that passes
	// all checks the owner of the SA.
	AnyQueue   = -1
	maxRowBits = 24 // Keeps at least 7 random bits in each SPI.
)

var (
	ErrUnknownSA = errors.New("engine: no receive SA for the SPI")
	ErrNoSeq     = errors.New("engine: flag S is not set")
	ErrVNI       = errors.New("engine: VNI does not match the SA")
	ErrLimit     = errors.New("engine: sequence number is at or above the SA packet limit")
	ErrSource    = errors.New("engine: inner source is not allowed for the SA")
	ErrReplay    = errors.New("engine: sequence number is a replay or too old")
	ErrFull      = errors.New("engine: no free receive row")
	// ErrHandoff tells that the packet went to the owner queue of its SA.
	ErrHandoff = errors.New("engine: packet went to the owner queue of the SA")
	// ErrHandoffDrop tells that the packet dropped: too many packets wait for
	// the owner queue, or another queue became the owner of the SA first.
	ErrHandoffDrop = errors.New("engine: packet dropped at the hand-off to the owner queue")
)

// RxConfig configures an RxTable.
type RxConfig struct {
	// RowBits is log2 of the row count, 1 to 24. Row 0 is not used. Each SPI
	// has the master key index in bit 31, then 31-RowBits random bits, then
	// the row index.
	RowBits int
	// Lifetime is how long an SA stays after Add. Expire removes it after that.
	Lifetime time.Duration
	// Queues is the number of receive queues, 1 to MaxQueues. Default 1.
	Queues int
}

// RxSA is a receive SA for Add.
type RxSA struct {
	Master      []byte // The SA key is KDF(Master, SPI).
	MasterIndex int    // 0 or 1. Bit 31 of the SPI.
	Version     psp.Version
	VNI         uint32
	Sources     []netip.Prefix // Allowed inner source addresses.
	MTU         int            // Inner MTU. It sets the packet limit.
	Lane        int            // Owner queue, or AnyQueue.
}

// RxStats are the counters of one receive SA.
type RxStats struct {
	Packets     uint64 // Accepted packets.
	ICVFailures uint64 // Packets that did not authenticate.
	Replays     uint64 // Authenticated packets that the replay window dropped.
	Rejects     uint64 // Other authenticated packets that a check dropped.
	Seq         uint32 // Highest accepted sequence number, or 0.
}

// RxTable holds the receive rows and the receive queues.
type RxTable struct {
	rows     []atomic.Pointer[rxRow]
	rowBits  uint
	rowMask  uint32
	lifetime time.Duration
	queues   []*RxQueue

	mu    sync.Mutex // Serializes Add, Delete and Expire.
	next  []uint32   // For each row, the random SPI bits of the next Add.
	left  []uint32   // For each row, how many new SPIs it can still give.
	free  []uint32   // FIFO ring of free rows, so that rows are used in turn.
	head  int
	nfree int
}

type rxRow struct {
	spi     uint32
	version psp.Version
	vni     uint32
	limit   uint32
	maxLen  int   // Longest PSP packet that a hand-off copies.
	expires int64 // Unix nanoseconds.
	aead    cipher.AEAD
	sources []netip.Prefix
	owner   atomic.Int32 // Owner queue. AnyQueue until the first packet passes.

	// Only the owner queue writes these, except that ICV failures and rejects
	// can come from any queue while the owner is AnyQueue.
	window                                 replay.Window
	seq                                    atomic.Uint32 // window.Last() for Stats.
	packets, icvFailures, replays, rejects atomic.Uint64

	// The inbox lock of the owner queue guards these.
	handoffGen uint64
	handoffs   int
}

// NewRxTable returns an empty receive table.
func NewRxTable(cfg RxConfig) (*RxTable, error) {
	if cfg.RowBits == 0 {
		cfg.RowBits = DefaultRowBits
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = DefaultLifetime
	}
	if cfg.Queues == 0 {
		cfg.Queues = 1
	}
	if cfg.RowBits < 1 || cfg.RowBits > maxRowBits {
		return nil, fmt.Errorf("engine: RowBits must be 1 to %d, got %d", maxRowBits, cfg.RowBits)
	}
	if cfg.Lifetime < 0 {
		return nil, fmt.Errorf("engine: Lifetime must be positive, got %v", cfg.Lifetime)
	}
	if cfg.Queues < 1 || cfg.Queues > MaxQueues {
		return nil, fmt.Errorf("engine: Queues must be 1 to %d, got %d", MaxQueues, cfg.Queues)
	}
	n := 1 << cfg.RowBits
	t := &RxTable{
		rows:     make([]atomic.Pointer[rxRow], n),
		rowBits:  uint(cfg.RowBits),
		rowMask:  uint32(n - 1),
		lifetime: cfg.Lifetime,
		next:     make([]uint32, n),
		left:     make([]uint32, n),
		free:     make([]uint32, n),
	}
	for i := range cfg.Queues {
		t.queues = append(t.queues, newRxQueue(t, i))
	}
	seed := make([]byte, 4*n)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	for r := 1; r < n; r++ {
		t.next[r] = binary.LittleEndian.Uint32(seed[4*r:])
		t.left[r] = 1 << (31 - t.rowBits)
		t.release(uint32(r))
	}
	return t, nil
}

// Add installs a receive SA in a free row. It returns the SPI and the SA key,
// which the receiver gives to the sender.
func (t *RxTable) Add(sa RxSA) (uint32, []byte, error) {
	switch {
	case len(sa.Master) != psp.MasterKeyLen:
		return 0, nil, fmt.Errorf("engine: master key must be %d bytes, got %d", psp.MasterKeyLen, len(sa.Master))
	case sa.MasterIndex < 0 || sa.MasterIndex >= psp.NumMasterKeys:
		return 0, nil, fmt.Errorf("engine: master key index must be 0 or 1, got %d", sa.MasterIndex)
	case !sa.Version.Valid():
		return 0, nil, psp.ErrVersion
	case sa.VNI > psp.MaxVNI:
		return 0, nil, psp.ErrVNI
	case sa.MTU <= 0:
		return 0, nil, fmt.Errorf("engine: MTU must be positive, got %d", sa.MTU)
	case sa.Lane != AnyQueue && (sa.Lane < 0 || sa.Lane >= len(t.queues)):
		return 0, nil, fmt.Errorf("engine: lane must be AnyQueue or 0 to %d, got %d", len(t.queues)-1, sa.Lane)
	}
	for _, p := range sa.Sources {
		if !p.IsValid() {
			return 0, nil, fmt.Errorf("engine: invalid source prefix %v", p)
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nfree == 0 {
		return 0, nil, ErrFull
	}
	r := t.free[t.head]
	t.head = (t.head + 1) % len(t.free)
	t.nfree--

	hi := t.next[r] & (1<<(31-t.rowBits) - 1)
	spi := uint32(sa.MasterIndex)<<31 | hi<<t.rowBits | r
	t.next[r]++
	t.left[r]--
	key, err := psp.DeriveSAKey(sa.Master, spi, sa.Version)
	if err != nil {
		t.release(r)
		return 0, nil, err
	}
	aead, err := psp.NewAEAD(key)
	if err != nil {
		t.release(r)
		return 0, nil, err
	}
	row := &rxRow{
		spi:     spi,
		version: sa.Version,
		vni:     sa.VNI,
		limit:   psp.PacketLimit(sa.MTU),
		maxLen:  sa.MTU + psp.Overhead,
		expires: time.Now().Add(t.lifetime).UnixNano(),
		aead:    aead,
		sources: slices.Clone(sa.Sources),
	}
	row.owner.Store(int32(sa.Lane))
	t.rows[r].Store(row)
	return spi, key, nil
}

// Delete removes the SA with the SPI and reports whether it was there. Its
// packets drop from then on.
func (t *RxTable) Delete(spi uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := spi & t.rowMask
	if row := t.rows[r].Load(); row == nil || row.spi != spi {
		return false
	}
	t.remove(r)
	return true
}

// Expire removes the SAs whose lifetime ended at or before now, and returns
// how many it removed.
func (t *RxTable) Expire(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ns := 0, now.UnixNano()
	for r := range t.rows {
		if row := t.rows[r].Load(); row != nil && row.expires <= ns {
			t.remove(uint32(r))
			n++
		}
	}
	return n
}

// Stats returns the counters of the SA with the SPI.
func (t *RxTable) Stats(spi uint32) (RxStats, bool) {
	row := t.rows[spi&t.rowMask].Load()
	if row == nil || row.spi != spi {
		return RxStats{}, false
	}
	return RxStats{
		Packets:     row.packets.Load(),
		ICVFailures: row.icvFailures.Load(),
		Replays:     row.replays.Load(),
		Rejects:     row.rejects.Load(),
		Seq:         row.seq.Load(),
	}, true
}

// Lifetime returns how long an SA stays after Add.
func (t *RxTable) Lifetime() time.Duration { return t.lifetime }

// Queues returns the number of receive queues.
func (t *RxTable) Queues() int { return len(t.queues) }

// Queue returns receive queue i.
func (t *RxTable) Queue(i int) *RxQueue { return t.queues[i] }

// check runs the checks that do not change the row state.
func (row *rxRow) check(h *psp.Header, inner []byte) error {
	switch {
	case h.Flags&psp.FlagSeq == 0:
		return ErrNoSeq
	case h.VNI != row.vni:
		return ErrVNI
	case h.Seq >= row.limit:
		return ErrLimit
	}
	src, ok := innerSource(inner)
	if !ok {
		return ErrSource
	}
	for _, p := range row.sources {
		if p.Contains(src) {
			return nil
		}
	}
	return ErrSource
}

// innerSource returns the source address of an IPv4 or IPv6 packet. psp.Open
// already checked that inner is not empty.
func innerSource(inner []byte) (netip.Addr, bool) {
	switch {
	case inner[0]>>4 == 4 && len(inner) >= 20:
		return netip.AddrFrom4([4]byte(inner[12:16])), true
	case inner[0]>>4 == 6 && len(inner) >= 40:
		return netip.AddrFrom16([16]byte(inner[8:24])), true
	}
	return netip.Addr{}, false
}

// remove clears row r and frees it. t.mu must be held.
func (t *RxTable) remove(r uint32) {
	t.rows[r].Store(nil)
	t.release(r)
}

// release puts row r at the end of the free ring, if it can still give a new
// SPI. t.mu must be held.
func (t *RxTable) release(r uint32) {
	if t.left[r] == 0 {
		return
	}
	t.free[(t.head+t.nfree)%len(t.free)] = r
	t.nfree++
}
