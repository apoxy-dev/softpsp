/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Apoxy changed this file for softpsp.

// Package replay implements an efficient anti-replay algorithm as specified in
// RFC 6479, on the 32-bit PSP sequence number.
package replay

const (
	blockBitLog = 6                // 1<<6 == 64 bits
	blockBits   = 1 << blockBitLog // must be power of 2
	ringBlocks  = 1 << 6           // must be power of 2; 512 bytes
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1

	// WindowSize is how far behind the highest sequence number a new one can be.
	WindowSize = (ringBlocks - 1) * blockBits
)

// Window rejects replayed sequence numbers with a sliding window. The zero
// value is an empty window. A Window is not safe for concurrent use.
type Window struct {
	last uint32
	ring [ringBlocks]uint64
}

// Check reports whether seq is new, and marks it as seen.
func (w *Window) Check(seq uint32) bool {
	indexBlock := seq >> blockBitLog
	if seq > w.last { // move window forward
		current := w.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks // cap diff to clear the whole ring
		}
		for i := current + 1; i <= current+diff; i++ {
			w.ring[i&blockMask] = 0
		}
		w.last = seq
	} else if w.last-seq > WindowSize { // behind current window
		return false
	}

	// check and set bit
	idx := indexBlock & blockMask
	bit := uint64(1) << (seq & bitMask)
	old := w.ring[idx]
	w.ring[idx] = old | bit
	return old&bit == 0
}

// Last returns the highest sequence number that Check accepted, or 0.
func (w *Window) Last() uint32 { return w.last }
