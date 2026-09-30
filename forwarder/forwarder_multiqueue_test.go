// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

//go:build linux

package forwarder_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/softpsp/forwarder"
	"github.com/apoxy-dev/softpsp/veth"
)

// TestForwarderMultiQueue drives the REAL AF_XDP decap datapath through a
// MULTI-QUEUE forwarder: phy and virt veths with several queues, so NewForwarder
// binds one phy/virt socket pair per queue and Start spawns one processFrames
// goroutine per queue — all decapsulating through the SAME shared decapPipe at
// once. TestForwarderDecapRoundTrip covers only the single-queue path; this test
// covers the multiqueue path on a real kernel.
//
// It injects many distinct inner flows. Each flow gets a different outer UDP
// source port, so the veth's RX hashing spreads the encapsulated frames across
// the queues and several processFrames goroutines do real concurrent decap work.
// The assertion is that EVERY distinct flow's canary is recovered on the virt
// side: a wedged or mis-bound queue goroutine would silently swallow the flows
// hashed to it, and a concurrency bug in the datapath would corrupt or drop
// frames. Run under -race (the dagger Integration lane default) it also
// exercises the N-goroutine datapath for data races that the single-queue tests
// cannot reach.
func TestForwarderMultiQueue(t *testing.T) {
	requireForwarderEnv(t)

	const numQueues = 4

	phyDev, err := veth.Create("icx-mqphy", numQueues, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyDev.Close()) })

	virtDev, err := veth.Create("icx-mqvirt", numQueues, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, virtDev.Close()) })

	h := &decapPipe{virtMAC: virtDev.Peer.Attrs().HardwareAddr}

	// No WithPhyFilter: use the production default phy filter (filter.Geneve on UDP
	// 6081), so this test also exercises the geneve.c XDP program — the production
	// ingress path, which no other test covers — under multiqueue. The injected
	// frames carry outer UDP dst port 6081, matching the filter's wildcard bind.
	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
	)
	require.NoError(t, err)

	// Start the forwarder and shut it down cleanly at test end (cancel + wait for
	// Start to self-close); see runForwarder for why a t.Cleanup(fwd.Close()) races
	// the still-running datapath goroutines.
	runForwarder(t, fwd)

	// Build a distinct inner flow per canary: distinct inner source address and a
	// unique 32-byte canary payload, so a recovered frame is unambiguously
	// attributable to its flow. Each flow gets its own outer source port, which
	// spreads the flows across the RX queues.
	const flows = 16
	innerIPs := make([][]byte, flows)
	virtFrames := make([][]byte, flows)
	for k := 0; k < flows; k++ {
		canary := []byte(fmt.Sprintf("icx-mq-canary-%02d-padding-xxxxx", k))
		ethL := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, byte(0x10 + k)},
			DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipL := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 99, 0, byte(10+k)),
			DstIP:    net.IPv4(10, 99, 0, 200),
		}
		udpL := &layers.UDP{SrcPort: layers.UDPPort(1234 + k), DstPort: 5678}
		require.NoError(t, udpL.SetNetworkLayerForChecksum(ipL))
		sb := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(sb,
			gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			ethL, ipL, udpL, gopacket.Payload(canary)))
		virtFrames[k] = sb.Bytes()
		innerIPs[k] = append([]byte(nil), virtFrames[k][14:]...) // IP packet the forwarder recovers
	}

	// Raw reader on the virt peer's far end.
	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	require.NoError(t, unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  virtDev.Link.Attrs().Index,
	}))

	// Raw sender on the phy peer's far end.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	phyDstMAC := phyDev.Peer.Attrs().HardwareAddr
	phySrcMAC := phyDev.Link.Attrs().HardwareAddr
	sa := &unix.SockaddrLinklayer{Ifindex: phyDev.Link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], phyDstMAC)

	// Let the forwarder bind all queues and attach XDP.
	time.Sleep(500 * time.Millisecond)

	seen := make([]bool, flows)
	remaining := flows
	recvBuf := make([]byte, 2048)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) && remaining > 0 {
		// Inject one frame for every flow this round.
		for k := 0; k < flows; k++ {
			enc := encapFrame(t, innerIPs[k], uint16(49152+k))
			copy(enc[0:6], phyDstMAC)
			copy(enc[6:12], phySrcMAC)
			require.NoError(t, unix.Sendto(sendFD, enc, 0, sa))
		}

		// Drain and attribute whatever decapped frames arrived.
		pfd := []unix.PollFd{{Fd: int32(recvFD), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		for {
			nr, _, rerr := unix.Recvfrom(recvFD, recvBuf, unix.MSG_DONTWAIT)
			if rerr != nil || nr <= 0 {
				break
			}
			frame := recvBuf[:nr]
			for k := 0; k < flows; k++ {
				if seen[k] {
					continue
				}
				if len(frame) >= 14+len(innerIPs[k]) && bytes.Equal(frame[14:14+len(innerIPs[k])], innerIPs[k]) {
					seen[k] = true
					remaining--
				}
			}
		}
	}

	if remaining > 0 {
		var missing []int
		for k := 0; k < flows; k++ {
			if !seen[k] {
				missing = append(missing, k)
			}
		}
		t.Fatalf("multiqueue decap dropped %d/%d flows (missing flow indices %v); a queue goroutine wedged or mis-bound, or the forwarder corrupted frames under concurrency",
			remaining, flows, missing)
	}
}
