// SPDX-License-Identifier: AGPL-3.0-only

// Package keys creates and changes PSP SAs. Each receiver creates its SAs as
// (SPI, KDF(master, SPI)) and gives each one to one sender in a Request. The
// same code serves the peer session and the relay session.
//
// A Request holds raw keys. Send it only inside the mTLS session to the sender.
package keys

import (
	"errors"
	"time"

	"github.com/apoxy-dev/softpsp/engine"
)

// MaxLanes is the largest number of SAs that a receiver gives to one sender.
const MaxLanes = engine.MaxQueues

// ErrBusy is the Rotate error while SAs of the old master key in the other slot
// are live.
var ErrBusy = errors.New("keys: SAs of the other master key are still live")

// SA is a receive SA that a receiver gives to one sender.
type SA struct {
	SPI       uint32
	Key       []byte // 16 bytes for AES-GCM-128, 32 bytes for AES-GCM-256.
	VNI       uint32
	ExpiresIn time.Duration // Time from receipt until the SA expires.
	Lane      int           // The receiver gives lane i to its receive queue i.
}

// Op is the kind of a Request.
type Op uint8

const (
	OpOffer  Op = iota + 1 // New SAs.
	OpRekey                // SAs that replace the SAs of the same lanes.
	OpRevoke               // SPIs whose receive state is gone.
)

// Request is one key change from a receiver to a sender.
type Request struct {
	Op   Op
	SAs  []SA     // OpOffer and OpRekey.
	SPIs []uint32 // OpRevoke.
}
