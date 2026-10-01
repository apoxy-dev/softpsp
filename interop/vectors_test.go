// SPDX-License-Identifier: AGPL-3.0-only

package interop

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/apoxy-dev/softpsp/psp"
)

const vectorsFile = "testdata/vectors.json"

// Sealer values of a packet vector.
const (
	sealerRef     = "google/psp" // psp_encrypt made PSP from Inner.
	sealerSoftPSP = "softpsp"    // psp.Seal made PSP, and psp_decrypt gave back Inner.
)

type vectors struct {
	Ref        string      `json:"ref"`
	MasterKeys [2]hexBytes `json:"master_keys"`
	KDF        []kdfVector `json:"kdf"`
	Packets    []pktVector `json:"packets"`
}

// kdfVector is an SA key that the reference derived.
type kdfVector struct {
	SPI   uint32      `json:"spi"`
	Suite psp.Version `json:"suite"`
	Key   hexBytes    `json:"key"`
}

type pktVector struct {
	Sealer string      `json:"sealer"`
	Suite  psp.Version `json:"suite"`
	SPI    uint32      `json:"spi"`
	IV     uint64      `json:"iv"`
	VNI    uint32      `json:"vni"`
	Flags  uint8       `json:"flags"`
	Seq    uint32      `json:"seq"`
	Inner  hexBytes    `json:"inner"`
	PSP    hexBytes    `json:"psp"`
}

func (v pktVector) name() string {
	return fmt.Sprintf("%s/v%d/IPv%d/%d", v.Sealer, v.Suite, v.Inner[0]>>4, len(v.Inner))
}

func (v pktVector) header() psp.Header {
	nh := uint8(psp.NextHdrV4)
	if v.Inner[0]>>4 == 6 {
		nh = psp.NextHdrV6
	}
	return psp.Header{NextHdr: nh, Version: v.Suite, SPI: v.SPI, IV: v.IV, VNI: v.VNI, Flags: v.Flags, Seq: v.Seq}
}

type hexBytes []byte

func (b hexBytes) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(b)), nil }

func (b *hexBytes) UnmarshalText(s []byte) error {
	d, err := hex.DecodeString(string(s))
	*b = d
	return err
}

// TestVectors checks the codec and the KDF against the reference output in
// testdata/vectors.json.
func TestVectors(t *testing.T) {
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var vs vectors
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs.KDF) == 0 || len(vs.Packets) == 0 {
		t.Fatal("no vectors")
	}
	for _, kv := range vs.KDF {
		t.Run(fmt.Sprintf("kdf/v%d/%08x", kv.Suite, kv.SPI), func(t *testing.T) {
			if got := deriveKey(t, vs.MasterKeys, kv.SPI, kv.Suite); !bytes.Equal(got, kv.Key) {
				t.Fatalf("SA key\n got %x\nwant %x", got, []byte(kv.Key))
			}
		})
	}
	for _, pv := range vs.Packets {
		t.Run(pv.name(), func(t *testing.T) { checkPacket(t, vs.MasterKeys, pv) })
	}
}

func deriveKey(t *testing.T, masters [2]hexBytes, spi uint32, suite psp.Version) []byte {
	t.Helper()
	key, err := psp.DeriveSAKey(masters[psp.MasterKeyIndex(spi)], spi, suite)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// checkPacket checks that the codec seals v.Inner to exactly v.PSP on both
// paths, and that it parses and opens v.PSP to v.Inner on both paths.
func checkPacket(t *testing.T, masters [2]hexBytes, v pktVector) {
	t.Helper()
	aead, err := psp.NewAEAD(deriveKey(t, masters, v.SPI, v.Suite))
	if err != nil {
		t.Fatal(err)
	}
	h := v.header()

	got := make([]byte, len(v.Inner)+psp.Overhead)
	if _, err := psp.Seal(aead, h, got, v.Inner); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !bytes.Equal(got, v.PSP) {
		t.Fatalf("Seal\n got %x\nwant %x", got, []byte(v.PSP))
	}
	buf := append(make([]byte, psp.PrefixLen), v.Inner...)
	buf = append(buf, make([]byte, psp.ICVLen)...)
	if _, _, err := psp.SealInPlace(aead, h, buf, psp.PrefixLen, len(v.Inner)); err != nil {
		t.Fatalf("SealInPlace: %v", err)
	}
	if !bytes.Equal(buf, v.PSP) {
		t.Fatalf("SealInPlace\n got %x\nwant %x", buf, []byte(v.PSP))
	}

	ph, err := psp.ParseHeader(v.PSP)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if ph != h {
		t.Fatalf("header\n got %+v\nwant %+v", ph, h)
	}
	n, err := psp.Open(aead, got, v.PSP)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got[:n], v.Inner) {
		t.Fatalf("Open\n got %x\nwant %x", got[:n], []byte(v.Inner))
	}
	inner, err := psp.OpenInPlace(aead, bytes.Clone(v.PSP))
	if err != nil {
		t.Fatalf("OpenInPlace: %v", err)
	}
	if !bytes.Equal(inner, v.Inner) {
		t.Fatalf("OpenInPlace\n got %x\nwant %x", inner, []byte(v.Inner))
	}
}
