// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

//go:build linux

package filter

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// requireLoad fails the test with the full verifier log when a program did
// not load. A process with no rights to load BPF programs gets skipOrFail.
func requireLoad(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) {
		skipOrFail(t, "cannot load BPF programs: %v", err)
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("the kernel rejects the program: %v\n%+v", err, ve)
	}
	require.NoError(t, err)
}

// TestProgramsLoad loads the relay program in each build that the loader can
// ask for. The kernel test of the CI runs it on each supported kernel.
func TestProgramsLoad(t *testing.T) {
	type loadCase struct {
		name string
		cfg  RelayConfig
	}
	var cases []loadCase

	meters := []struct {
		name string
		cfg  RelayConfig
	}{
		{"no meter", RelayConfig{}},
		{"lane meter", RelayConfig{LaneRate: 1e6, LaneBurst: 1e5}},
		{"tunnel limit", RelayConfig{TunnelRate: 1e6, TunnelBurst: 1e5}},
		{"lane meter and tunnel limit", RelayConfig{LaneRate: 1e6, LaneBurst: 1e5, TunnelRate: 1e6, TunnelBurst: 1e5}},
	}
	sends := []struct {
		name     string
		redirect bool
	}{
		{"XDP_TX", false},
		{"redirect", true},
	}
	hops := []struct {
		name  string
		cache time.Duration
	}{
		{"route lookup", 0},
		{"next hop cache", time.Second},
	}
	for _, m := range meters {
		for _, s := range sends {
			for _, h := range hops {
				cfg := m.cfg
				cfg.Port, cfg.MaxLen = relayPort, testMaxLen
				cfg.Redirect, cfg.NextHopCache = s.redirect, h.cache
				cases = append(cases, loadCase{"relay/" + m.name + "/" + s.name + "/" + h.name, cfg})
			}
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRelay(tc.cfg)
			requireLoad(t, err)
			require.NoError(t, r.Close())
		})
	}
}
