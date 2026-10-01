// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

// ErrRouteTaken is the Add error when another peer has the prefix.
var ErrRouteTaken = errors.New("engine: another peer has the route")

// Routes maps inner IPv4 and IPv6 prefixes to peers (cryptokey routing). The
// send side finds the peer of a destination with Lookup. The receive SAs of a
// peer check inner sources with Sources. Add and Remove change one route: they
// copy only the nodes on its path and publish the new table version. Lookup
// reads the current version with no lock. The zero value is an empty table.
type Routes[V comparable] struct {
	mu  sync.Mutex // Serializes Add and Remove.
	cur atomic.Pointer[bart.Fast[route[V]]]
}

// route wraps the peer, so that bart never calls a Clone method of V when it
// copies a node. Sources compares the peers.
type route[V comparable] struct{ peer V }

// Lookup returns the peer of the longest prefix that contains a.
func (r *Routes[V]) Lookup(a netip.Addr) (V, bool) {
	t := r.cur.Load()
	if t == nil {
		var zero V
		return zero, false
	}
	rt, ok := t.Lookup(a)
	return rt.peer, ok
}

// Sources returns the source check of the receive SAs of peer: an address is
// allowed if its route goes to peer. Route changes apply at once.
func (r *Routes[V]) Sources(peer V) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		p, ok := r.Lookup(a)
		return ok && p == peer
	}
}

// Add routes the prefix p to peer. It returns ErrRouteTaken if another peer
// has p. Adding a route that peer already has does nothing.
func (r *Routes[V]) Add(p netip.Prefix, peer V) error {
	if !p.IsValid() {
		return fmt.Errorf("engine: invalid prefix %v", p)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.table()
	if old, ok := t.Get(p); ok {
		if old.peer != peer {
			return ErrRouteTaken
		}
		return nil
	}
	r.cur.Store(t.InsertPersist(p, route[V]{peer}))
	return nil
}

// Remove removes the route of the prefix p if peer has it, and reports whether
// it removed it.
func (r *Routes[V]) Remove(p netip.Prefix, peer V) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.table()
	if old, ok := t.Get(p); !ok || old.peer != peer {
		return false
	}
	r.cur.Store(t.DeletePersist(p))
	return true
}

// Len returns the number of routes.
func (r *Routes[V]) Len() int { return r.table().Size() }

func (r *Routes[V]) table() *bart.Fast[route[V]] {
	if t := r.cur.Load(); t != nil {
		return t
	}
	return new(bart.Fast[route[V]])
}
