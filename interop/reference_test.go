// SPDX-License-Identifier: AGPL-3.0-only

package interop

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/apoxy-dev/softpsp/psp"
)

var update = flag.Bool("update", false, "write "+vectorsFile+" from the google/psp run")

// The master keys of the google/psp test configs and the PSP spec examples.
var masterKeys = [2]hexBytes{
	mustHex("34448a064292601b11a0978f56a2d34cf3fc35ede1a6bc04f8db3e5243a2b0ca"),
	mustHex("563952565d3a78ae773ec1b779f2f2d99f4a7f53a6fbb9b07d5b71f39364d739"),
}

// SPIs for the KDF vectors: both master keys, and the first and last SPIs.
var kdfSPIs = []uint32{0x00000001, 0x12345678, 0x7fffffff, 0x80000001, 0x9a345678, 0xffffffff}

// TestReference runs psp_encrypt and psp_decrypt from PSP_REF_DIR (google/psp
// at PSP_REF_COMMIT) against the codec in both directions. Then it compares the
// result with vectorsFile, or writes the file with -update.
func TestReference(t *testing.T) {
	dir, commit := os.Getenv("PSP_REF_DIR"), os.Getenv("PSP_REF_COMMIT")
	if dir == "" {
		t.Skip("PSP_REF_DIR is not set. The CI Interop lane sets it.")
	}
	if commit == "" {
		t.Fatal("PSP_REF_COMMIT is not set")
	}
	r := &refRunner{t: t, dir: dir, tmp: t.TempDir()}
	got := vectors{Ref: "github.com/google/psp@" + commit, MasterKeys: masterKeys}

	for _, suite := range []psp.Version{psp.AESGCM128, psp.AESGCM256} {
		for _, spi := range kdfSPIs {
			key := r.refKey(suite, spi)
			if want := deriveKey(t, masterKeys, spi, suite); !bytes.Equal(key, want) {
				t.Fatalf("v%d SPI %08x: psp_encrypt key %x, DeriveSAKey %x", suite, spi, key, want)
			}
			got.KDF = append(got.KDF, kdfVector{SPI: spi, Suite: suite, Key: key})
		}
		for _, ipv := range []int{4, 6} {
			spi := uint32(0x12345678)
			if ipv == 6 {
				spi = 0x9a345678 // Master key 1.
			}
			got.Packets = append(got.Packets, r.refSeals(suite, spi, ipv)...)
			got.Packets = append(got.Packets, r.softpspSeals(suite, spi, ipv)...)
		}
	}

	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorsFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsFile, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("%s differs from the google/psp run. Run this test with -update and commit the file.", vectorsFile)
	}
}

type refRunner struct {
	t   *testing.T
	dir string // psp_encrypt and psp_decrypt.
	tmp string
	n   int // Makes file names unique.
}

// refSeals checks packets that psp_encrypt seals and the codec opens. The
// reference always writes a zero VC and starts the IV at 1.
func (r *refRunner) refSeals(suite psp.Version, spi uint32, ipv int) []pktVector {
	inners := innerPackets(ipv)
	frames := r.encrypt(suite, spi, inners)
	var vs []pktVector
	for i, f := range frames {
		v := pktVector{Sealer: sealerRef, Suite: suite, SPI: spi, IV: uint64(i + 1), Inner: inners[i], PSP: pspPayload(r.t, f)}
		r.t.Run(v.name(), func(t *testing.T) { checkPacket(t, masterKeys, v) })
		vs = append(vs, v)
	}

	// psp_encrypt -e sets an R bit after it computes the ICV. ParseHeader
	// ignores R bits, so Open must find the change.
	for _, f := range r.encrypt(suite, spi, inners, "-e") {
		pkt := pspPayload(r.t, f)
		if _, err := psp.ParseHeader(pkt); err != nil {
			r.t.Fatalf("ParseHeader of a psp_encrypt -e packet: %v", err)
		}
		aead := newAEAD(r.t, spi, suite)
		if _, err := psp.Open(aead, make([]byte, len(pkt)), pkt); !errors.Is(err, psp.ErrAuth) {
			r.t.Fatalf("Open of a psp_encrypt -e packet: got %v, want %v", err, psp.ErrAuth)
		}
	}
	return vs
}

// softpspSeals checks packets that the codec seals with a VC and psp_decrypt
// opens.
func (r *refRunner) softpspSeals(suite psp.Version, spi uint32, ipv int) []pktVector {
	aead := newAEAD(r.t, spi, suite)
	inners := innerPackets(ipv)
	var vs []pktVector
	var frames [][]byte
	for i, inner := range inners {
		v := pktVector{Sealer: sealerSoftPSP, Suite: suite, SPI: spi, IV: 0x0102030405060708 + uint64(i),
			VNI: 0x123456 + uint32(i), Flags: psp.FlagSeq, Seq: 0x0a0b0c0d + uint32(i), Inner: inner}
		v.PSP = make([]byte, len(inner)+psp.Overhead)
		if _, err := psp.Seal(aead, v.header(), v.PSP, inner); err != nil {
			r.t.Fatal(err)
		}
		vs = append(vs, v)
		frames = append(frames, outerFrame(ipv, v.PSP))
	}

	out, err := r.decrypt(frames)
	if err != nil {
		r.t.Fatalf("psp_decrypt: %v", err)
	}
	if len(out) != len(inners) {
		r.t.Fatalf("psp_decrypt gave %d packets, want %d", len(out), len(inners))
	}
	for i, f := range out {
		if got := f[14:]; !bytes.Equal(got, inners[i]) {
			r.t.Fatalf("psp_decrypt packet %d\n got %x\nwant %x", i, got, inners[i])
		}
	}

	// One changed ciphertext bit must fail the reference ICV check.
	bad := bytes.Clone(frames[0])
	bad[len(bad)-psp.ICVLen-1] ^= 0x01
	if _, err := r.decrypt([][]byte{bad}); err == nil {
		r.t.Fatal("psp_decrypt accepted a packet with a changed ciphertext bit")
	}
	return vs
}

// encrypt runs psp_encrypt in tunnel mode with a VC and crypt offset 2 on
// Ethernet frames of the inner packets, and returns its output frames.
func (r *refRunner) encrypt(suite psp.Version, spi uint32, inners [][]byte, args ...string) [][]byte {
	in, out := r.path("clear.pcap"), r.path("enc.pcap")
	var frames [][]byte
	for _, p := range inners {
		frames = append(frames, ethFrame(p))
	}
	writePcap(r.t, in, frames)
	r.run("psp_encrypt", append([]string{"-c", r.encryptCfg(suite, spi), "-i", in, "-o", out}, args...)...)
	return readPcap(r.t, out)
}

// decrypt runs psp_decrypt on frames and returns its output frames.
func (r *refRunner) decrypt(frames [][]byte) ([][]byte, error) {
	in, out, cfg := r.path("psp.pcap"), r.path("dec.pcap"), r.path("dec.cfg")
	writePcap(r.t, in, frames)
	writeFile(r.t, cfg, fmt.Sprintf("% x\n% x\n", []byte(masterKeys[0]), []byte(masterKeys[1])))
	if _, err := r.exec("psp_decrypt", "-c", cfg, "-i", in, "-o", out); err != nil {
		return nil, err
	}
	return readPcap(r.t, out), nil
}

// refKey returns the SA key that psp_encrypt -v prints.
func (r *refRunner) refKey(suite psp.Version, spi uint32) []byte {
	in := r.path("kdf.pcap")
	writePcap(r.t, in, [][]byte{ethFrame(innerPackets(4)[0])})
	stdout := r.run("psp_encrypt", "-v", "-c", r.encryptCfg(suite, spi), "-i", in, "-o", r.path("kdf-out.pcap"))
	_, after, ok := strings.Cut(stdout, "Derived Key:\n")
	line, _, _ := strings.Cut(after, "\n")
	key, err := hex.DecodeString(strings.ReplaceAll(line, " ", ""))
	if !ok || err != nil || len(key) != suite.KeyLen() {
		r.t.Fatalf("no derived key in psp_encrypt output:\n%s", stdout)
	}
	return key
}

// encryptCfg writes a psp_encrypt config: tunnel mode, crypt offset 2 for
// IPv4 and IPv6, with a VC.
func (r *refRunner) encryptCfg(suite psp.Version, spi uint32) string {
	alg := "aes-gcm-128"
	if suite == psp.AESGCM256 {
		alg = "aes-gcm-256"
	}
	p := r.path("enc.cfg")
	writeFile(r.t, p, fmt.Sprintf("% x\n% x\n%08X\ntunnel\n%s\n2\n2\n2\nvc\n", []byte(masterKeys[0]), []byte(masterKeys[1]), spi, alg))
	return p
}

func (r *refRunner) path(name string) string {
	r.n++
	return filepath.Join(r.tmp, fmt.Sprintf("%03d-%s", r.n, name))
}

func (r *refRunner) run(name string, args ...string) string {
	out, err := r.exec(name, args...)
	if err != nil {
		r.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func (r *refRunner) exec(name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(filepath.Join(r.dir, name), args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String() + stderr.String(), err
}

func newAEAD(t *testing.T, spi uint32, suite psp.Version) cipher.AEAD {
	t.Helper()
	a, err := psp.NewAEAD(deriveKey(t, masterKeys, spi, suite))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// innerPackets returns IPv4 or IPv6 UDP packets with 0, 92 and 272 payload
// bytes. The largest is more than 16 AES blocks, so the 8-block GCM code runs.
func innerPackets(ipv int) [][]byte {
	var ps [][]byte
	for _, n := range []int{0, 92, 272} {
		ps = append(ps, udpPacket(ipv, n))
	}
	return ps
}

// udpPacket returns an IPv4 or IPv6 packet with a UDP header and n payload
// bytes. The reference code reads the UDP ports.
func udpPacket(ipv, n int) []byte {
	ipLen := 20
	if ipv == 6 {
		ipLen = 40
	}
	p := make([]byte, ipLen+8+n)
	if ipv == 4 {
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		binary.BigEndian.PutUint16(p[6:], 0x4000) // DF.
		p[8], p[9] = 64, 17
		copy(p[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
		binary.BigEndian.PutUint16(p[10:], ipv4Checksum(p[:20]))
	} else {
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(8+n))
		p[6], p[7] = 17, 64
		p[8], p[9], p[23] = 0xfd, 0x00, 1
		p[24], p[25], p[39] = 0xfd, 0x00, 2
	}
	udp := p[ipLen:]
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 5201)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+n))
	for i := range n {
		udp[8+i] = byte(i)
	}
	return p
}

// outerFrame wraps a PSP packet in Ethernet, IP and UDP to port 1000, which
// psp_decrypt reads.
func outerFrame(ipv int, pkt []byte) []byte {
	udp := make([]byte, 8+len(pkt))
	binary.BigEndian.PutUint16(udp[0:], 50000)
	binary.BigEndian.PutUint16(udp[2:], 1000)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], pkt)
	var ip []byte
	if ipv == 4 {
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8], ip[9] = 64, 17
		copy(ip[12:], []byte{192, 0, 2, 1, 192, 0, 2, 2})
		binary.BigEndian.PutUint16(ip[10:], ipv4Checksum(ip))
	} else {
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
		ip[6], ip[7] = 17, 64
		ip[8], ip[9], ip[23] = 0x20, 0x01, 1
		ip[24], ip[25], ip[39] = 0x20, 0x01, 2
	}
	return ethFrame(append(ip, udp...))
}

func ethFrame(ip []byte) []byte {
	eth := []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00}
	if ip[0]>>4 == 6 {
		eth[12], eth[13] = 0x86, 0xdd
	}
	return append(eth, ip...)
}

// pspPayload returns the UDP payload of an Ethernet frame from psp_encrypt.
func pspPayload(t *testing.T, f []byte) []byte {
	t.Helper()
	off := 14 + 20 + 8
	if f[12] == 0x86 && f[13] == 0xdd {
		off = 14 + 40 + 8
	}
	if len(f) < off+psp.Overhead {
		t.Fatalf("short psp_encrypt frame: %x", f)
	}
	return f[off:]
}

func ipv4Checksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func writePcap(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	var b bytes.Buffer
	w := pcapgo.NewWriter(&b)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(0, 0), CaptureLength: len(f), Length: len(f)}
		if err := w.WritePacket(ci, f); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, path, b.String())
}

func readPcap(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			return frames
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, data)
	}
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
