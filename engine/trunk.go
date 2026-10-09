// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"net/netip"

	"github.com/apoxy-dev/softpsp/psp"
)

// The trunk functions are apart from Seal, Receive and Open, so that the
// other SAs pay nothing for them.

// noSource is the source check of a trunk row.
func noSource(netip.Addr) bool { return false }

// SealTrunk is Seal on a trunk SA. The tag goes in the VNI field, so a tag
// above psp.MaxVNI gives psp.ErrVNI.
func (s *TxSA) SealTrunk(tag uint32, dst, inner []byte) (int, error) {
	seq, err := s.Reserve()
	if err != nil {
		return 0, err
	}
	h := psp.Header{Version: s.version, SPI: s.spi, IV: seq, VNI: tag, Flags: psp.FlagSeq, Seq: uint32(seq)}
	return psp.Seal(s.aead, h, dst, inner)
}

// SealTrunkPSP is SealTrunk for a payload that is a whole PSP packet, for
// example the packet of an agent that a relay sends on. It does not read pkt.
func (s *TxSA) SealTrunkPSP(tag uint32, dst, pkt []byte) (int, error) {
	seq, err := s.Reserve()
	if err != nil {
		return 0, err
	}
	h := psp.Header{Version: s.version, SPI: s.spi, IV: seq, VNI: tag, Flags: psp.FlagSeq, Seq: uint32(seq)}
	return psp.SealPSP(s.aead, h, dst, pkt)
}

// ReceiveTrunk is Receive for a trunk SA. The caller checks the tag and the
// payload. There is no hand-off: a packet for the SA of another queue drops.
func (q *RxQueue) ReceiveTrunk(pkt []byte) (payload []byte, tag uint32, nextHdr uint8, err error) {
	h, err := psp.ParseTrunkHeader(pkt)
	if err != nil {
		q.nomatch.Add(1)
		return nil, 0, 0, err
	}
	row := q.t.rows[h.SPI&q.t.rowMask].Load()
	if row == nil || row.spi != h.SPI || row.version != h.Version || !row.trunk {
		q.nomatch.Add(1)
		return nil, 0, 0, ErrUnknownSA
	}
	owner := row.owner.Load()
	if owner != q.id && owner != AnyQueue {
		q.handoffDrops.Add(1)
		return nil, 0, 0, ErrHandoffDrop
	}
	payload, err = psp.OpenTrunkInPlace(row.aead, pkt)
	if errors.Is(err, psp.ErrAuth) {
		row.icvFailures.Add(1)
		return nil, 0, 0, err
	}
	if err == nil {
		err = row.checkTrunk(&h)
	}
	if err != nil {
		row.rejects.Add(1)
		return nil, 0, 0, err
	}
	if owner == AnyQueue && !row.owner.CompareAndSwap(AnyQueue, q.id) && row.owner.Load() != q.id {
		q.handoffDrops.Add(1)
		return nil, 0, 0, ErrHandoffDrop
	}
	if row.noReplay {
		// Stats gives seq to the rekey at the packet limit, so keep it
		// with no window too.
		if h.Seq > row.seq.Load() {
			row.seq.Store(h.Seq)
		}
	} else {
		if !row.window.Check(h.Seq) {
			row.replays.Add(1)
			return nil, 0, 0, ErrReplay
		}
		row.seq.Store(row.window.Last())
	}
	row.packets.Add(1)
	return payload, h.VNI, h.NextHdr, nil
}

// checkTrunk is check for a trunk row: no VNI and no inner source.
func (row *rxRow) checkTrunk(h *psp.Header) error {
	switch {
	case h.Flags&psp.FlagSeq == 0:
		return ErrNoSeq
	case h.Seq >= row.limit:
		return ErrLimit
	case row.noReplay && h.NextHdr != psp.NextHdrPSP:
		return ErrPayload
	}
	return nil
}
