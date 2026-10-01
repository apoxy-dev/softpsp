/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Apoxy changed this file for softpsp.

package replay

import (
	"encoding/binary"
	"math"
	"testing"
	"unsafe"
)

type step struct {
	seq  uint32
	want bool
}

// run returns the steps for seq = from, from+inc, ... to (inclusive).
func run(from, to uint32, inc int, want bool) []step {
	var s []step
	for i := int64(from); ; i += int64(inc) {
		s = append(s, step{uint32(i), want})
		if i == int64(to) {
			return s
		}
	}
}

func join(parts ...[]step) []step {
	var s []step
	for _, p := range parts {
		s = append(s, p...)
	}
	return s
}

func TestWindow(t *testing.T) {
	const lim = WindowSize + 1
	const top = math.MaxUint32
	cases := []struct {
		name  string
		steps []step
	}{
		{"wireguard", []step{
			{0, true}, {1, true}, {1, false}, {9, true}, {8, true}, {7, true}, {7, false},
			{lim, true}, {lim - 1, true}, {lim - 1, false}, {lim - 2, true}, {2, true}, {2, false},
			{lim + 16, true}, {3, false}, {lim + 16, false}, {lim * 4, true}, {lim*4 - (lim - 1), true},
			{10, false}, {lim*4 - lim, false}, {lim*4 - (lim + 1), false}, {lim*4 - (lim - 2), true},
			{lim*4 + 1 - lim, false}, {0, false},
		}},
		{"in order then 0", join(run(1, WindowSize, 1, true), []step{{0, true}, {0, false}})},
		{"in order from 2 then 1", join(run(2, WindowSize+1, 1, true), []step{{1, true}, {0, false}})},
		{"reverse", run(WindowSize+1, 1, -1, true)},
		{"reverse from 2", join(run(WindowSize+2, 2, -1, true), []step{{0, false}})},
		{"reverse then ahead", join(run(WindowSize, 1, -1, true), []step{{WindowSize + 1, true}, {0, false}})},
		{"reverse then 0", join(run(WindowSize, 1, -1, true), []step{{0, true}, {WindowSize + 1, true}})},
		{"duplicates", []step{{5, true}, {5, false}, {6, true}, {5, false}, {6, false}, {4, true}}},
		{"window edge", []step{{lim + 9, true}, {9, false}, {10, true}, {10, false}}},
		{"top of range", []step{
			{top - 1, true}, {top, true}, {top, false}, {top - 1, false},
			{top - WindowSize, true}, {top - WindowSize - 1, false}, {0, false},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w Window
			var last uint32
			for i, s := range tc.steps {
				if got := w.Check(s.seq); got != s.want {
					t.Fatalf("step %d: Check(%d) = %v, want %v", i, s.seq, got, s.want)
				}
				if s.want {
					last = max(last, s.seq)
				}
				if w.Last() != last {
					t.Fatalf("step %d: Last() = %d, want %d", i, w.Last(), last)
				}
			}
		})
	}
}

func TestWindowSize(t *testing.T) {
	if n := unsafe.Sizeof(Window{}); n > 520 {
		t.Fatalf("Window is %d bytes, want at most 520", n)
	}
}

// FuzzWindow compares Window with a simple model: a sequence number is new if
// it was not seen and it is at most WindowSize below the highest one seen.
func FuzzWindow(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1, 0x80, 0, 0, 2, 0xff, 0xff})
	f.Add([]byte{0x7f, 0xff, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		var w Window
		seen := map[uint32]bool{}
		var last uint32
		for i := 0; i+1 < len(data); i += 2 {
			// Each step moves around the window edge: a signed delta from the
			// highest sequence number, times 8 when the low bit is set.
			d := int64(int16(binary.BigEndian.Uint16(data[i:])))
			if d&1 != 0 {
				d *= 8
			}
			s := int64(last) + d
			if s < 0 || s > math.MaxUint32 {
				continue
			}
			seq := uint32(s)
			want := !seen[seq] && (seq > last || last-seq <= WindowSize)
			if got := w.Check(seq); got != want {
				t.Fatalf("Check(%d) after last %d = %v, want %v", seq, last, got, want)
			}
			if want {
				seen[seq] = true
				last = max(last, seq)
			}
		}
	})
}

func BenchmarkWindow(b *testing.B) {
	cases := []struct {
		name string
		next func(i uint32) uint32
	}{
		{"in order", func(i uint32) uint32 { return i }},
		{"reorder", func(i uint32) uint32 { return i ^ 7 }}, // Blocks of 8 in reverse order.
		{"replay", func(i uint32) uint32 { return 1000 }},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var w Window
			var i uint32
			b.ReportAllocs()
			for b.Loop() {
				w.Check(tc.next(i))
				i++
			}
		})
	}
}
