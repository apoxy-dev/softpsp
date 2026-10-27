// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
)

func trunkSA() RxSA {
	return RxSA{Master: testMaster, Version: psp.AESGCM128, MTU: 1412, Trunk: true}
}

// sealTo seals payload for tx with the VNI field tag: as a message between
// relays, or as an IP packet.
func sealTo(tb testing.TB, tx *TxSA, tag uint32, payload []byte, isMessage bool) []byte {
	tb.Helper()
	h := psp.Header{Version: tx.version, SPI: tx.spi, VNI: tag, Flags: psp.FlagSeq}
	pkt := make([]byte, len(payload)+psp.Overhead)
	seal := psp.Seal
	if isMessage {
		seal = psp.SealMessage
	}
	if _, err := seal(tx.aead, h, pkt, payload); err != nil {
		tb.Fatal(err)
	}
	return pkt
}

// TestTrunkModes checks that Receive and Open drop each packet of a trunk SA,
// and that a plain SA refuses a message as the payload.
func TestTrunkModes(t *testing.T) {
	vni := testSA().VNI
	receive := func(q *RxQueue, pkt []byte) error {
		_, _, err := q.Receive(pkt)
		return err
	}
	open := func(q *RxQueue, pkt []byte) error {
		_, _, err := q.Open(pkt)
		return err
	}
	cases := []struct {
		name      string
		sa        RxSA
		tag       uint32
		isMessage bool
		recv      func(q *RxQueue, pkt []byte) error
		want      error
		stats     RxStats
		queue     QueueStats
	}{
		{name: "plain SA, message, Receive", sa: testSA(), tag: vni, isMessage: true, recv: receive,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, message, Open", sa: testSA(), tag: vni, isMessage: true, recv: open,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
		{name: "plain SA, IP packet, Receive", sa: testSA(), tag: vni, recv: receive,
			stats: RxStats{Packets: 1}},
		{name: "trunk SA, IP packet, Receive", sa: trunkSA(), recv: receive,
			want: ErrSource, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, IP packet with a tag, Receive", sa: trunkSA(), tag: 5, recv: receive,
			want: ErrVNI, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, IP packet, Open", sa: trunkSA(), recv: open,
			want: ErrSource, stats: RxStats{Rejects: 1}},
		{name: "trunk SA, message, Receive", sa: trunkSA(), isMessage: true, recv: receive,
			want: psp.ErrNextHdr, queue: QueueStats{NoMatch: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, 4)
			tx := addTx(t, tab, tc.sa)
			q := tab.Queue(0)
			if err := tc.recv(q, sealTo(t, tx, tc.tag, ipPacket(src4, 100), tc.isMessage)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if st, _ := tab.Stats(tx.SPI()); st != tc.stats {
				t.Fatalf("stats %+v, want %+v", st, tc.stats)
			}
			if st := q.Stats(); st != tc.queue {
				t.Fatalf("queue stats %+v, want %+v", st, tc.queue)
			}
		})
	}
}

func TestTrunkAdd(t *testing.T) {
	tab := newTable(t, 4)
	cases := []struct {
		name string
		edit func(*RxSA)
	}{
		{"trunk SA with a VNI", func(sa *RxSA) { sa.VNI = 1 }},
		{"trunk SA with a source check", func(sa *RxSA) { sa.Sources = testRoutes.Sources("test") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sa := trunkSA()
			tc.edit(&sa)
			if _, _, err := tab.Add(sa); err == nil {
				t.Fatal("Add accepted the SA")
			}
		})
	}
}
