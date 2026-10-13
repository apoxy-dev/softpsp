// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

// Package main is the softpsp Dagger CI/test harness.
//
// It has four lanes, which run locally (`dagger call <fn>`) and in GitHub
// Actions:
//
//   - Unit: go build and go vet over the module, then the tests minus the
//     root-requiring datapath packages, unprivileged, race detector on.
//   - Integration: the whole tree WITH the root capability set, on a real
//     kernel, so the veth/AF_XDP/forwarder tests actually run.
//   - Interop: the interop tests against the google/psp reference code.
//   - Kernels: the test that loads the relay XDP program, on each supported
//     kernel in a QEMU guest.
//
// Every command is run as a real argv — no `sh -c` — so there is no
// shell-quoting surface; the package filtering for Unit is done in Go against
// `go list` output.
package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"dagger/softpsp/internal/dagger"
)

const goImage = "golang:1.26.8-bookworm"

// The google/psp commit that the Interop lane builds. interop/testdata has
// its output, so a change here needs new vectors (see the interop package).
const (
	pspRefRepo   = "https://github.com/google/psp"
	pspRefCommit = "8ac5fc19be57fbff18f44bb0b1d8e91c34b7260a"
)

// vimtoPkg is the tool that runs a Go test in a QEMU guest.
const vimtoPkg = "lmb.io/vimto@v0.4.0"

// kernelImage has a kernel at /boot/vmlinuz for each of its tags.
const kernelImage = "ghcr.io/cilium/ci-kernels"

// loadTest is the test that loads the relay XDP program.
const loadTest = "TestProgramsLoad"

// requireBPFEnv makes a filter test fail where it skips for a lack of rights.
// The lanes that give the tests those rights set it.
const requireBPFEnv = "SOFTPSP_REQUIRE_BPF"

// defaultKernels are the long-term kernels that have all helpers of the
// program (Linux 5.11), and the newest stable kernel.
var defaultKernels = []string{"5.15", "6.1", "6.6", "6.12", "stable"}

// privilegedPkgRe matches the packages whose tests need the root capability
// set: they create veth pairs / AF_XDP sockets. Unit filters them out of
// `go list`; Integration runs the whole tree with privilege, so it covers them.
var privilegedPkgRe = regexp.MustCompile(`/(forwarder|internal/xsk|veth)($|/)`)

type Softpsp struct{}

// BuilderContainer is the base Go toolchain image with shared module/build
// caches and iproute2, which the forwarder test uses to build veth pairs and a
// netns. The repo source is mounted at /src.
func (m *Softpsp) BuilderContainer(src *dagger.Directory) *dagger.Container {
	return goContainer("iproute2").
		WithDirectory("/src", src).
		WithWorkdir("/src")
}

// goContainer is the Go toolchain image with the shared module and build
// caches and the given Debian packages.
func goContainer(pkgs ...string) *dagger.Container {
	return dag.Container().
		From(goImage).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("softpsp-go-mod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/go/build-cache", dag.CacheVolume("softpsp-go-build")).
		WithEnvVariable("GOCACHE", "/go/build-cache").
		WithExec([]string{"apt-get", "update", "-qq"}).
		WithExec(append([]string{"apt-get", "install", "-y", "-qq"}, pkgs...))
}

// Unit runs go build and go vet over the module, then the tests WITHOUT extra
// privilege: the module minus the root-requiring datapath packages (see
// privilegedPkgRe), race detector on by default, test cache disabled. For the
// privileged lane that exercises the veth/AF_XDP datapath, use Integration.
func (m *Softpsp) Unit(
	ctx context.Context,
	src *dagger.Directory,
	// Run with the race detector (-race). Default true.
	// +optional
	// +default=true
	race bool,
) (string, error) {
	c := m.BuilderContainer(src).
		WithExec([]string{"go", "build", "./..."}).
		WithExec([]string{"go", "vet", "./..."})
	if out, err := execStdout(ctx, c); err != nil {
		return out, fmt.Errorf("build and vet: %w", err)
	}
	pkgs, err := testPkgs(ctx, c, privilegedPkgRe)
	if err != nil {
		return "", err
	}
	return runSuite(ctx, c, goTestArgs(race), pkgs, false)
}

// Integration runs the FULL suite on a real kernel with the root capability set
// (InsecureRootCapabilities) so the AF_XDP/XSK socket setup, veth creation and
// XDP redirect-program load actually run rather than failing on EPERM. It is
// the superset of the Unit tests.
//
// It is safe on a kernel without CONFIG_XDP_SOCKETS — the AF_XDP tests probe
// for it at runtime and skip cleanly; the lane just covers less.
func (m *Softpsp) Integration(
	ctx context.Context,
	src *dagger.Directory,
	// Run with the race detector (-race). Default true.
	// +optional
	// +default=true
	race bool,
) (string, error) {
	c := m.BuilderContainer(src).WithEnvVariable(requireBPFEnv, "1")
	return runSuite(ctx, c, goTestArgs(race), []string{"./..."}, true)
}

// Kernels loads the relay XDP program on each kernel, which is a tag of
// ghcr.io/cilium/ci-kernels. A QEMU guest without KVM runs the load test, so
// each runner can run it. A kernel that rejects the program fails the call.
func (m *Softpsp) Kernels(
	ctx context.Context,
	src *dagger.Directory,
	// Kernels to test. The default is 5.15, 6.1, 6.6, 6.12 and stable.
	// +optional
	kernels []string,
) (string, error) {
	if len(kernels) == 0 {
		kernels = defaultKernels
	}
	platform, err := dag.DefaultPlatform(ctx)
	if err != nil {
		return "", fmt.Errorf("default platform: %w", err)
	}
	qemu := "qemu-system-x86"
	if strings.HasPrefix(string(platform), "linux/arm64") {
		qemu = "qemu-system-arm"
	}
	c := m.BuilderContainer(src).
		WithExec([]string{"apt-get", "install", "-y", "-qq", "--no-install-recommends", qemu}).
		// vimto runs only as a static binary.
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "install", vimtoPkg}).
		WithoutEnvVariable("CGO_ENABLED").
		WithEnvVariable("VIMTO_DISABLE_KVM", "true").
		WithEnvVariable(requireBPFEnv, "1")

	var b strings.Builder
	var errs []error
	for _, k := range kernels {
		fmt.Fprintf(&b, "===== kernel %s =====\n", k)
		vmlinuz := dag.Container().From(kernelImage + ":" + k).File("/boot/vmlinuz")
		out, err := execStdout(ctx, c.
			WithFile("/kernel/vmlinuz", vmlinuz).
			WithExec([]string{
				// One CPU: a guest without KVM can panic at boot when a second CPU
				// takes an interrupt while the kernel changes its code. The load test needs one.
				"vimto", "-kernel", "/kernel/vmlinuz", "-memory", "size=1G", "-smp", "cpus=1", "--",
				"go", "test", "-count=1", "-v", "-run", "^" + loadTest + "$", "./filter",
			}))
		b.WriteString(out)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("kernel %s: %w", k, err))
		case !strings.Contains(out, "--- PASS: "+loadTest+" ") || strings.Contains(out, "--- SKIP: "):
			// A run with no test or with a skip also exits with 0.
			errs = append(errs, fmt.Errorf("kernel %s: the load test did not run all cases", k))
		}
	}
	return b.String(), errors.Join(errs...)
}

// Interop builds psp_encrypt and psp_decrypt from google/psp and runs the
// interop tests with them: the codec and the KDF against the reference in both
// directions, and interop/testdata against the reference output.
func (m *Softpsp) Interop(ctx context.Context, src *dagger.Directory) (string, error) {
	c := goContainer("libpcap-dev", "libssl-dev").
		WithDirectory("/psp", dag.Git(pspRefRepo).Commit(pspRefCommit).Tree()).
		WithExec([]string{"make", "-C", "/psp/src", "psp_encrypt", "psp_decrypt"}).
		WithEnvVariable("PSP_REF_DIR", "/psp/src").
		WithEnvVariable("PSP_REF_COMMIT", pspRefCommit).
		WithDirectory("/src", src).
		WithWorkdir("/src")
	return runSuite(ctx, c, goTestArgs(false), []string{"./interop/..."}, false)
}

// goTestArgs is the `go test` flag vector shared by the lanes.
func goTestArgs(race bool) []string {
	args := []string{"-count=1", "-v"}
	if race {
		args = append(args, "-race")
	}
	return args
}

// testPkgs lists the module packages, dropping any whose import path matches
// exclude (nil = keep all). The filter runs in Go against `go list` output
// rather than a shell pipeline.
func testPkgs(ctx context.Context, c *dagger.Container, exclude *regexp.Regexp) ([]string, error) {
	out, err := c.WithExec([]string{"go", "list", "./..."}).Stdout(ctx)
	if err != nil {
		return nil, fmt.Errorf("go list packages: %w", err)
	}
	var pkgs []string
	for _, p := range strings.Fields(out) {
		if exclude != nil && exclude.MatchString(p) {
			continue
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	return pkgs, nil
}

// runSuite runs `go test <testArgs> <pkgs>` in the module. privileged toggles
// the full root capability set for the kernel/datapath tests.
func runSuite(ctx context.Context, c *dagger.Container, testArgs, pkgs []string, privileged bool) (string, error) {
	opts := dagger.ContainerWithExecOpts{InsecureRootCapabilities: privileged}
	cmd := append(append([]string{"go", "test"}, testArgs...), pkgs...)
	out, err := execStdout(ctx, c.WithExec(cmd, opts))
	if err != nil {
		return out, fmt.Errorf("tests: %w", err)
	}
	return out, nil
}

// execStdout returns the container's stdout, recovering the captured output from
// the ExecError when the command exits non-zero — Dagger otherwise discards it,
// so a failing lane would return an error with no test log.
func execStdout(ctx context.Context, c *dagger.Container) (string, error) {
	out, err := c.Stdout(ctx)
	if err != nil {
		var ee *dagger.ExecError
		if errors.As(err, &ee) {
			return ee.Stdout + ee.Stderr, err
		}
	}
	return out, err
}
