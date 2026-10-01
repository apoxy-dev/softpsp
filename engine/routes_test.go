// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	pfx  = netip.MustParsePrefix
	addr = netip.MustParseAddr
)

func TestRoutesLookup(t *testing.T) {
	var r Routes[string]
	for p, peer := range map[string]string{
		"0.0.0.0/0":     "relay",
		"10.0.0.0/8":    "a",
		"10.1.0.0/16":   "b",
		"10.1.2.3/32":   "c",
		"::/0":          "relay",
		"fd00::/8":      "a",
		"fd00:1::/64":   "b",
		"fd00:1::5/128": "c",
	} {
		if err := r.Add(pfx(p), peer); err != nil {
			t.Fatal(err)
		}
	}
	var v4only Routes[string]
	v4only.Add(pfx("10.0.0.0/8"), "a")

	cases := []struct {
		r    *Routes[string]
		addr string
		want string // Empty: no route.
	}{
		{&r, "10.2.0.1", "a"},
		{&r, "10.1.9.9", "b"},
		{&r, "10.1.2.3", "c"},
		{&r, "10.1.2.4", "b"},
		{&r, "192.0.2.1", "relay"},
		{&r, "fd00:2::1", "a"},
		{&r, "fd00:1::6", "b"},
		{&r, "fd00:1::5", "c"},
		{&r, "2001:db8::1", "relay"},
		{&v4only, "10.9.9.9", "a"},
		{&v4only, "11.0.0.1", ""},
		{&v4only, "fd00::1", ""},
		{&v4only, "::ffff:10.9.9.9", ""}, // An IPv4-mapped address is IPv6.
		{new(Routes[string]), "10.0.0.1", ""},
	}
	for _, tc := range cases {
		got, ok := tc.r.Lookup(addr(tc.addr))
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("Lookup(%s) = %q, %v, want %q", tc.addr, got, ok, tc.want)
		}
	}
}

func TestRoutesChanges(t *testing.T) {
	var r Routes[string]
	add := func(p netip.Prefix, peer string) error { return r.Add(p, peer) }
	remove := func(p netip.Prefix, peer string) error {
		if !r.Remove(p, peer) {
			return errNotRemoved
		}
		return nil
	}
	steps := []struct {
		name   string
		op     func(netip.Prefix, string) error
		prefix netip.Prefix
		peer   string
		want   error
		len    int
	}{
		{"add", add, pfx("10.0.0.0/8"), "a", nil, 1},
		{"add again", add, pfx("10.0.0.0/8"), "a", nil, 1},
		{"add for other peer", add, pfx("10.0.0.0/8"), "b", ErrRouteTaken, 1},
		{"add not masked", add, pfx("10.1.2.3/8"), "b", ErrRouteTaken, 1},
		{"add inside", add, pfx("10.1.0.0/16"), "b", nil, 2},
		{"add IPv6", add, pfx("fd00::/8"), "a", nil, 3},
		{"remove not there", remove, pfx("10.2.0.0/16"), "a", errNotRemoved, 3},
		{"remove of other peer", remove, pfx("10.0.0.0/8"), "b", errNotRemoved, 3},
		{"remove invalid", remove, netip.Prefix{}, "a", errNotRemoved, 3},
		{"remove", remove, pfx("10.0.0.0/8"), "a", nil, 2},
		{"remove again", remove, pfx("10.0.0.0/8"), "a", errNotRemoved, 2},
		{"remove not masked", remove, pfx("fd00::1/8"), "a", nil, 1},
	}
	for _, st := range steps {
		err := st.op(st.prefix, st.peer)
		if !errors.Is(err, st.want) {
			t.Fatalf("%s: got %v, want %v", st.name, err, st.want)
		}
		if r.Len() != st.len {
			t.Fatalf("%s: %d routes, want %d", st.name, r.Len(), st.len)
		}
	}
	for a, want := range map[string]string{"10.1.2.3": "b", "10.2.0.0": "", "fd00::1": ""} {
		if got, _ := r.Lookup(addr(a)); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", a, got, want)
		}
	}
	if err := r.Add(netip.Prefix{}, "a"); err == nil || r.Len() != 1 {
		t.Errorf("Add of an invalid prefix: %v", err)
	}
}

var errNotRemoved = errors.New("not removed")

type testPeer struct{ id int }

// TestRoutesConcurrent looks up routes while a writer adds and removes others.
// Routes that do not change must always be found.
func TestRoutesConcurrent(t *testing.T) {
	const n = 100
	var r Routes[*testPeer]
	stable, churn := make([]*testPeer, n), make([]*testPeer, n)
	for i := range n {
		stable[i], churn[i] = &testPeer{i}, &testPeer{n + i}
		r.Add(pfx(fmt.Sprintf("10.0.%d.0/24", i)), stable[i])
		r.Add(pfx(fmt.Sprintf("fd00:%x::/64", i)), stable[i])
	}
	// The writer adds and removes routes inside the stable ones (overlaps) and
	// outside them.
	churnPrefixes := func(i int) []netip.Prefix {
		return []netip.Prefix{
			pfx(fmt.Sprintf("10.0.%d.128/25", i)),
			pfx(fmt.Sprintf("10.1.%d.0/24", i)),
			pfx(fmt.Sprintf("fd00:%x::8000:0:0:0/65", i)),
			pfx(fmt.Sprintf("fd01:%x::/64", i)),
		}
	}
	var done atomic.Bool
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for i := 0; !done.Load(); i = (i + 1) % n {
				for _, a := range []string{fmt.Sprintf("10.0.%d.1", i), fmt.Sprintf("fd00:%x::1", i)} {
					if p, ok := r.Lookup(addr(a)); !ok || p != stable[i] {
						t.Errorf("Lookup(%s) = %v, want stable peer %d", a, p, i)
						return
					}
				}
				for _, a := range []string{fmt.Sprintf("10.0.%d.200", i), fmt.Sprintf("fd00:%x::8000:0:0:1", i)} {
					if p, ok := r.Lookup(addr(a)); !ok || (p != stable[i] && p != churn[i]) {
						t.Errorf("Lookup(%s) = %v, want peer %d or %d", a, p, i, n+i)
						return
					}
				}
				if p, ok := r.Lookup(addr(fmt.Sprintf("10.1.%d.1", i))); ok && p != churn[i] {
					t.Errorf("Lookup(10.1.%d.1) = %v, want peer %d or none", i, p, n+i)
					return
				}
			}
		})
	}
	for round := range 20 {
		for i := range n {
			for _, p := range churnPrefixes(i) {
				if round%2 == 0 {
					if err := r.Add(p, churn[i]); err != nil {
						t.Fatal(err)
					}
				} else if !r.Remove(p, churn[i]) {
					t.Fatalf("Remove(%v) found no route", p)
				}
			}
		}
	}
	done.Store(true)
	wg.Wait()
	if r.Len() != 2*n {
		t.Fatalf("%d routes, want %d", r.Len(), 2*n)
	}
}

// TestRoutesSources changes the routes while a receive SA uses them.
func TestRoutesSources(t *testing.T) {
	var r Routes[string]
	tab := newTable(t, 4)
	sa := testSA()
	sa.Sources = r.Sources("a")
	_, s := add(t, tab, sa)
	steps := []struct {
		name   string
		change func()
		want   error
	}{
		{"no route", func() {}, ErrSource},
		{"route to a", func() { r.Add(pfx("10.9.0.0/16"), "a") }, nil},
		{"longer route to b", func() { r.Add(pfx("10.9.0.0/24"), "b") }, ErrSource},
		{"remove route to b", func() { r.Remove(pfx("10.9.0.0/24"), "b") }, nil},
		{"remove route to a", func() { r.Remove(pfx("10.9.0.0/16"), "a") }, ErrSource},
		{"default route to a", func() { r.Add(pfx("0.0.0.0/0"), "a") }, nil},
	}
	for i, st := range steps {
		st.change()
		_, _, err := tab.Queue(0).Receive(s.seal(t, uint32(i), ipPacket(addr("10.9.0.1"), 60), nil))
		if !errors.Is(err, st.want) {
			t.Fatalf("%s: got %v, want %v", st.name, err, st.want)
		}
	}
}

func TestRoutesNoAllocs(t *testing.T) {
	r := benchRoutes(1000)
	sources := r.Sources(&testPeer{})
	for _, a := range []string{"10.0.0.1", "fd00::1", "192.0.2.1", "2001:db8::1"} {
		ip := addr(a)
		if n := testing.AllocsPerRun(100, func() { r.Lookup(ip); sources(ip) }); n != 0 {
			t.Errorf("Lookup(%s): %v allocs per run, want 0", a, n)
		}
	}
}

// attachmentRoutes returns the routes of n attachments: one random IPv6 /128
// and one random IPv4 /32 each, with no two the same.
func attachmentRoutes(n int) [][2]netip.Prefix {
	rng := rand.New(rand.NewPCG(1, 2))
	seen := map[netip.Prefix]bool{}
	var out [][2]netip.Prefix
	for len(out) < n {
		var a6 [16]byte
		a6[0] = 0xfd
		for i := 1; i < 16; i++ {
			a6[i] = byte(rng.Uint32())
		}
		v4 := rng.Uint32()
		p6 := netip.PrefixFrom(netip.AddrFrom16(a6), 128)
		p4 := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(v4 >> 16), byte(v4 >> 8), byte(v4)}), 32)
		if seen[p6] || seen[p4] {
			continue
		}
		seen[p6], seen[p4] = true, true
		out = append(out, [2]netip.Prefix{p6, p4})
	}
	return out
}

// benchRoutes returns a table with default routes and n attachments.
func benchRoutes(n int) *Routes[*testPeer] {
	r := new(Routes[*testPeer])
	relay := &testPeer{-1}
	r.Add(pfx("0.0.0.0/0"), relay)
	r.Add(pfx("::/0"), relay)
	for i, ps := range attachmentRoutes(n) {
		p := &testPeer{i}
		r.Add(ps[0], p)
		r.Add(ps[1], p)
	}
	return r
}

// BenchmarkRoutesGrow adds 5000 attachments one route at a time. It reports
// the mean time of one Add near 100, 1000 and 5000 attachments, and the live
// memory for each attachment (2 routes) at 5000.
func BenchmarkRoutesGrow(b *testing.B) {
	const n = 5000
	routes := attachmentRoutes(n)
	peers := make([]*testPeer, n)
	for i := range peers {
		peers[i] = &testPeer{i}
	}
	windows := []struct {
		name     string
		from, to int
	}{{"ns/add@100", 50, 150}, {"ns/add@1000", 950, 1050}, {"ns/add@5000", 4900, 5000}}
	sums := make([]time.Duration, len(windows))
	took := make([]time.Duration, n)
	var mem float64
	var rounds int
	for b.Loop() {
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		r := new(Routes[*testPeer])
		for i, ps := range routes {
			start := time.Now()
			r.Add(ps[0], peers[i])
			r.Add(ps[1], peers[i])
			took[i] = time.Since(start)
		}
		runtime.GC()
		runtime.ReadMemStats(&m1)
		runtime.KeepAlive(r)
		mem += float64(m1.HeapAlloc-m0.HeapAlloc) / n
		for w, win := range windows {
			for _, d := range took[win.from:win.to] {
				sums[w] += d
			}
		}
		rounds++
	}
	for w, win := range windows {
		b.ReportMetric(float64(sums[w].Nanoseconds())/float64(rounds*(win.to-win.from)*2), win.name)
	}
	b.ReportMetric(mem/float64(rounds), "B/attachment")
}

// BenchmarkRoutesAddRemove adds and removes one more attachment (2 routes) in a
// table with n attachments.
func BenchmarkRoutesAddRemove(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			r := benchRoutes(n)
			ps, peer := attachmentRoutes(n + 1)[n], &testPeer{}
			b.ReportAllocs()
			for b.Loop() {
				r.Add(ps[0], peer)
				r.Add(ps[1], peer)
				r.Remove(ps[0], peer)
				r.Remove(ps[1], peer)
			}
		})
	}
}

func BenchmarkRoutesLookup(b *testing.B) {
	const n = 5000
	r := benchRoutes(n)
	routes := attachmentRoutes(n)
	hits4, hits6 := make([]netip.Addr, n), make([]netip.Addr, n)
	for i, ps := range routes {
		hits6[i], hits4[i] = ps[0].Addr(), ps[1].Addr()
	}
	cases := []struct {
		name  string
		addrs []netip.Addr
	}{
		{"v4 hit", hits4},
		{"v6 hit", hits6},
		{"v4 default", []netip.Addr{addr("192.0.2.1"), addr("198.51.100.7")}},
		{"v6 default", []netip.Addr{addr("2001:db8::1"), addr("fd00::1")}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if _, ok := r.Lookup(tc.addrs[i]); !ok {
					b.Fatal("no route")
				}
				if i++; i == len(tc.addrs) {
					i = 0
				}
			}
		})
	}
}
