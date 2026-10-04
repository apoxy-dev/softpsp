// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
)

// addTx adds sa to t and returns a TxSA for it.
func addTx(tb testing.TB, t *RxTable, sa RxSA) *TxSA {
	tb.Helper()
	spi, key, err := t.Add(sa)
	if err != nil {
		tb.Fatal(err)
	}
	tx, err := NewTxSA(spi, key, sa.VNI, sa.MTU)
	if err != nil {
		tb.Fatal(err)
	}
	return tx
}

func TestTxSA(t *testing.T) {
	for _, v := range []psp.Version{psp.AESGCM128, psp.AESGCM256} {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			tab := newTable(t, 4)
			sa := testSA()
			sa.Version = v
			tx := addTx(t, tab, sa)
			inner := ipPacket(src4, 100)
			pkt := make([]byte, len(inner)+psp.Overhead)
			for seq := range uint32(3) {
				n, err := tx.Seal(pkt, inner)
				if err != nil {
					t.Fatal(err)
				}
				h, err := psp.ParseHeader(pkt[:n])
				if err != nil || h.Seq != seq || h.IV != uint64(seq) || h.Version != v || h.Flags != psp.FlagSeq {
					t.Fatalf("header %+v, %v: want seq and IV %d, version %d, flag S", h, err, seq, v)
				}
				got, vni, err := tab.Queue(0).Receive(pkt[:n])
				if err != nil || !bytes.Equal(got, inner) || vni != sa.VNI {
					t.Fatalf("Receive: VNI %#x, %v", vni, err)
				}
			}
		})
	}
}

func TestTxSALimit(t *testing.T) {
	tab := newTable(t, 4)
	tx := addTx(t, tab, testSA())
	tx.next.Store(uint64(tx.limit) - 1)
	inner := ipPacket(src4, 60)
	pkt := make([]byte, len(inner)+psp.Overhead)
	if _, err := tx.Seal(pkt, inner); err != nil {
		t.Fatalf("last sequence number: %v", err)
	}
	if _, _, err := tab.Queue(0).Receive(pkt); err != nil {
		t.Fatalf("Receive the last sequence number: %v", err)
	}
	for range 2 {
		if _, err := tx.Seal(pkt, inner); !errors.Is(err, ErrLimit) {
			t.Fatalf("Seal after the limit: got %v, want %v", err, ErrLimit)
		}
	}
}

// TestTxSAReserve reserves sequence numbers in order and seals the packets
// in another order. Sent in Reserve order, the receiver accepts all of them.
func TestTxSAReserve(t *testing.T) {
	const n = 64
	cases := []struct {
		name  string
		order func(i int) int // The index of the i-th seal.
	}{
		{"in order", func(i int) int { return i }},
		{"reverse", func(i int) int { return n - 1 - i }},
		{"interleaved", func(i int) int { return i/2 + i%2*(n/2) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, testSA())
			inner := ipPacket(src4, 100)
			seqs := make([]uint64, n)
			for i := range seqs {
				seq, err := tx.Reserve()
				if err != nil || seq != uint64(i) {
					t.Fatalf("Reserve %d: %d, %v", i, seq, err)
				}
				seqs[i] = seq
			}
			pkts := make([][]byte, n)
			for i := range n {
				j := tc.order(i)
				pkt := make([]byte, len(inner)+psp.Overhead)
				m, err := tx.SealSeq(seqs[j], pkt, inner)
				if err != nil {
					t.Fatal(err)
				}
				pkts[j] = pkt[:m]
			}
			for i, pkt := range pkts {
				h, err := psp.ParseHeader(pkt)
				if err != nil || h.Seq != uint32(i) || h.IV != uint64(i) {
					t.Fatalf("packet %d: header %+v, %v", i, h, err)
				}
				if got, _, err := tab.Queue(0).Receive(pkt); err != nil || !bytes.Equal(got, inner) {
					t.Fatalf("Receive %d: %v", i, err)
				}
			}
			tx.next.Store(uint64(tx.limit))
			if _, err := tx.Reserve(); !errors.Is(err, ErrLimit) {
				t.Fatalf("Reserve after the limit: got %v, want %v", err, ErrLimit)
			}
		})
	}
}

func TestNewTxSA(t *testing.T) {
	key := make([]byte, 16)
	cases := []struct {
		name string
		spi  uint32
		key  []byte
		vni  uint32
		mtu  int
		want error
	}{
		{"reserved SPI", 1 << 31, key, 1, 1280, psp.ErrSPI},
		{"VNI too big", 1, key, psp.MaxVNI + 1, 1280, psp.ErrVNI},
		{"MTU 0", 1, key, 1, 0, nil},
		{"key 20 bytes", 1, make([]byte, 20), 1, 1280, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTxSA(tc.spi, tc.key, tc.vni, tc.mtu)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want an error (%v)", err, tc.want)
			}
		})
	}
}

// TestTxSAConcurrent checks that goroutines that seal at once never use a
// sequence number twice.
func TestTxSAConcurrent(t *testing.T) {
	const goroutines, n = 8, 1000
	tx := addTx(t, newTable(t, 4), testSA())
	seqs := make([][]uint32, goroutines)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			inner := ipPacket(src4, 60)
			pkt := make([]byte, len(inner)+psp.Overhead)
			for range n {
				if _, err := tx.Seal(pkt, inner); err != nil {
					t.Error(err)
					return
				}
				h, _ := psp.ParseHeader(pkt)
				seqs[g] = append(seqs[g], h.Seq)
			}
		})
	}
	wg.Wait()
	seen := map[uint32]bool{}
	for _, s := range seqs {
		for _, seq := range s {
			if seen[seq] || seq >= goroutines*n {
				t.Fatalf("sequence number %d used twice or out of range", seq)
			}
			seen[seq] = true
		}
	}
}

func TestTxSANoAllocs(t *testing.T) {
	tx := addTx(t, newTable(t, 4), testSA())
	inner := ipPacket(src4, 1280)
	pkt := make([]byte, len(inner)+psp.Overhead)
	if a := testing.AllocsPerRun(100, func() {
		if _, err := tx.Seal(pkt, inner); err != nil {
			t.Fatal(err)
		}
	}); a != 0 {
		t.Fatalf("Seal: %v allocs per run, want 0", a)
	}
}

func BenchmarkTxSASeal(b *testing.B) {
	for _, n := range []int{64, 1280} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			tx := addTx(b, newTable(b, 4), testSA())
			inner := ipPacket(src4, n)
			pkt := make([]byte, len(inner)+psp.Overhead)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := tx.Seal(pkt, inner); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTxSACounter compares the atomic sequence counter of Seal with a
// plain counter when one goroutine seals. The parallel cases compare one TxSA
// for each goroutine, as with lanes, with one TxSA that all goroutines share.
func BenchmarkTxSACounter(b *testing.B) {
	for _, n := range []int{64, 1280} {
		tab := newTable(b, 8)
		var txs []*TxSA
		for range 64 {
			txs = append(txs, addTx(b, tab, testSA()))
		}
		tx := txs[0]
		inner := ipPacket(src4, n)
		b.Run(fmt.Sprintf("%d/atomic", n), func(b *testing.B) {
			pkt := make([]byte, len(inner)+psp.Overhead)
			for b.Loop() {
				tx.Seal(pkt, inner)
			}
		})
		b.Run(fmt.Sprintf("%d/plain", n), func(b *testing.B) {
			pkt := make([]byte, len(inner)+psp.Overhead)
			var next uint64
			for b.Loop() {
				seq := next
				next++
				h := psp.Header{Version: tx.version, SPI: tx.spi, IV: seq, VNI: tx.vni, Flags: psp.FlagSeq, Seq: uint32(seq)}
				psp.Seal(tx.aead, h, pkt, inner)
			}
		})
		for _, shared := range []bool{false, true} {
			name := map[bool]string{false: "parallel own", true: "parallel shared"}[shared]
			b.Run(fmt.Sprintf("%d/%s", n, name), func(b *testing.B) {
				var g atomic.Int32
				b.RunParallel(func(pb *testing.PB) {
					tx := txs[int(g.Add(1))%len(txs)]
					if shared {
						tx = txs[0]
					}
					pkt := make([]byte, len(inner)+psp.Overhead)
					for pb.Next() {
						tx.Seal(pkt, inner)
					}
				})
			})
		}
	}
}
