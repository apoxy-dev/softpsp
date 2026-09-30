//go:build linux

package forwarder_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/softpsp/filter"
	"github.com/apoxy-dev/softpsp/forwarder"
	"github.com/apoxy-dev/softpsp/veth"
)

// TestForwarderDecapRoundTrip drives a decap handler (decapPipe) through the
// real AF_XDP forwarder datapath over veth. TestForwarder uses an identity
// handler, so its output window is always the input window. Here the handler
// moves the window: the test injects an encapsulated physical frame at the
// forwarder's phy ingress and asserts the forwarder emits the recovered inner
// packet on the virt interface, byte-for-byte.
//
// The frame is injected via a raw AF_PACKET socket on the phy peer (the same
// XDP-redirect primitive TestForwarderRXHeadroom uses), and the decapped inner
// frame is read with a second raw socket on the virt peer.
func TestForwarderDecapRoundTrip(t *testing.T) {
	requireForwarderEnv(t)

	// phy/virt veth pairs. The forwarder binds to the .Peer ends; we inject on
	// phy.Link and read on virt.Link (the opposite ends), mirroring TestForwarder.
	phyDev, err := veth.Create("icx-cphy", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyDev.Close()) })

	virtDev, err := veth.Create("icx-cvirt", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, virtDev.Close()) })

	phyFilter, err := filter.All()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyFilter.Close()) })

	// The handler writes this MAC as the Ethernet destination of every decapped
	// frame; pin it to the virt interface's real MAC and assert it on the wire.
	virtMAC := virtDev.Peer.Attrs().HardwareAddr
	h := &decapPipe{virtMAC: virtMAC}

	// Build the forwarder with the decap handler (not the identity pipe).
	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(phyFilter),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
	)
	require.NoError(t, err)
	runForwarder(t, fwd)

	// The inner virtual frame: [Ethernet][IPv4][UDP][canary payload]. The canary
	// payload makes the decapped frame unmistakable amid any link-local noise on
	// the veth.
	canary := []byte("icx-decap-roundtrip-canary-00001")
	ethL := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipL := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(10, 99, 0, 1),
		DstIP:    net.IPv4(10, 99, 0, 2),
	}
	udpL := &layers.UDP{SrcPort: 1234, DstPort: 5678}
	require.NoError(t, udpL.SetNetworkLayerForChecksum(ipL))
	sb := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(sb,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethL, ipL, udpL, gopacket.Payload(canary)))
	virtFrame := sb.Bytes()
	innerIP := virtFrame[14:] // the IP packet the forwarder must recover

	// Raw reader on the virt peer's far end: the decapped frame the forwarder
	// transmits on virt.Peer arrives here.
	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	require.NoError(t, unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  virtDev.Link.Attrs().Index,
	}))

	// Raw sender on the phy peer's far end: a frame sent here ingresses phy.Peer,
	// where the XDP program redirects it into the forwarder's phy socket.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	phyDstMAC := phyDev.Peer.Attrs().HardwareAddr // forwarder's phy ingress
	phySrcMAC := phyDev.Link.Attrs().HardwareAddr
	sa := &unix.SockaddrLinklayer{Ifindex: phyDev.Link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], phyDstMAC)

	// Let the forwarder finish binding both sockets and attaching XDP.
	time.Sleep(500 * time.Millisecond)

	recvBuf := make([]byte, 2048)
	var found bool
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !found {
		enc := encapFrame(t, innerIP, 49152)

		// Steer the outer frame to the forwarder's phy ingress (the XDP redirect
		// is MAC-agnostic but we set a real dst/src to mirror
		// TestForwarderRXHeadroom).
		copy(enc[0:6], phyDstMAC)
		copy(enc[6:12], phySrcMAC)
		require.NoError(t, unix.Sendto(sendFD, enc, 0, sa))

		// Drain whatever arrived on the virt side and look for our inner packet.
		pfd := []unix.PollFd{{Fd: int32(recvFD), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		for {
			nr, _, rerr := unix.Recvfrom(recvFD, recvBuf, unix.MSG_DONTWAIT)
			if rerr != nil || nr <= 0 {
				break
			}
			frame := recvBuf[:nr]
			if len(frame) >= 14+len(innerIP) && bytes.Equal(frame[14:14+len(innerIP)], innerIP) {
				// The forwarder rewrote the Ethernet header with virtMAC as dst.
				require.Equal(t, []byte(virtMAC), frame[0:6],
					"decapped frame Ethernet destination should be the configured virt MAC")
				found = true
				break
			}
		}
	}

	require.True(t, found,
		"forwarder did not emit the decapsulated inner packet on the virt interface; "+
			"the in-place decap over the AF_XDP datapath failed")
}
