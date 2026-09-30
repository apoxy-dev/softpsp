//go:build linux

package forwarder_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/icx/udp"
)

// testUnderlayPort is the outer UDP destination port of the test frames. The
// default phy filter binds this port.
const testUnderlayPort = 6081

// testBaseHdr is a base Geneve header (version 0, no options, IPv4 payload). The
// test frames carry it so that the default phy filter accepts them.
var testBaseHdr = []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x12, 0x34, 0x00}

// decapPipe is a test engine without crypto. It removes the outer Ethernet,
// IP, UDP and base header in place, writes a new Ethernet header (destination
// virtMAC) before the inner IP packet and returns the moved window. It drops
// all frames from virt to phy.
type decapPipe struct {
	virtMAC net.HardwareAddr
}

func (e *decapPipe) PhyToVirtInPlace(buf []byte, off, length int) (int, int) {
	frame := buf[off : off+length]
	payload, err := udp.Decode(frame, nil, true)
	if err != nil || len(payload) <= len(testBaseHdr) || !bytes.Equal(payload[:len(testBaseHdr)], testBaseHdr) {
		return 0, 0
	}
	// The payload is a subslice of frame, so the difference in capacity is its offset.
	innerOff := off + cap(frame) - cap(payload) + len(testBaseHdr)
	ethOff := innerOff - 14
	copy(buf[ethOff:ethOff+6], e.virtMAC)
	copy(buf[ethOff+6:ethOff+12], []byte{0x02, 0, 0, 0, 0x0a, 0x01})
	buf[ethOff+12], buf[ethOff+13] = 0x08, 0x00
	return ethOff, 14 + len(payload) - len(testBaseHdr)
}

func (e *decapPipe) VirtToPhyInPlace(buf []byte, off, length int) (int, int, bool) {
	return 0, 0, false
}

func (e *decapPipe) ToPhyInPlace(buf []byte, off int) (int, int) {
	return 0, 0
}

// encapFrame builds an outer [Ethernet][IPv4][UDP][base header] frame around
// the inner IP packet. srcPort is the outer UDP source port.
func encapFrame(t *testing.T, inner []byte, srcPort uint16) []byte {
	t.Helper()
	ethL := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x0a, 0x02},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x0a, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipL := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(192, 168, 1, 2),
		DstIP:    net.IPv4(192, 168, 1, 1),
	}
	udpL := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: testUnderlayPort}
	require.NoError(t, udpL.SetNetworkLayerForChecksum(ipL))
	sb := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(sb,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethL, ipL, udpL, gopacket.Payload(append(append([]byte(nil), testBaseHdr...), inner...))))
	return sb.Bytes()
}
