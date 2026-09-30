//go:build linux

package forwarder_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/icx/forwarder"
)

// layer3Pipe is the identity pipe handler set to layer3 mode.
type layer3Pipe struct{ pipe }

func (layer3Pipe) IsLayer3() bool { return true }

// TestForwarderRejectsLayer3Handler proves NewForwarder fails closed when handed
// a handler in layer3 mode. The forwarder's virtual interface is an L2 veth; an
// in-place L3 decap writes a raw IP packet onto it, which the veth silently
// drops — the symptom that wedged a real-hardware userspace-tun <-> AF_XDP A/B
// to zero decap with no error. The guard runs before any NIC binding, so this
// needs no NET_ADMIN or real interface. The forwarder side must simply be L2.
func TestForwarderRejectsLayer3Handler(t *testing.T) {
	_, err := forwarder.NewForwarder(&layer3Pipe{},
		forwarder.WithPhyName("icx-nope-phy"),
		forwarder.WithVirtName("icx-nope-virt"),
	)
	require.Error(t, err, "NewForwarder must reject a layer3 handler")
	require.Contains(t, err.Error(), "layer3")
}
