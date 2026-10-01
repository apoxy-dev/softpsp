// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

// Package main is the softpsp Dagger CI/test harness.
//
// It has three lanes, which run locally (`dagger call <fn>`) and in GitHub
// Actions:
//
//   - Unit: go build and go vet over the module, then the tests minus the
//     root-requiring datapath packages, unprivileged, race detector on.
//   - Integration: the whole tree WITH the root capability set, on a real
//     kernel, so the veth/AF_XDP/forwarder tests actually run.
//   - Interop: the interop tests against the google/psp reference code.
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
// It is safe on a kernel without CONFIG_XDP_SOCKETS — the AF_XDP tests gate
// themselves at runtime and skip cleanly; the lane just covers less.
func (m *Softpsp) Integration(
	ctx context.Context,
	src *dagger.Directory,
	// Run with the race detector (-race). Default true.
	// +optional
	// +default=true
	race bool,
) (string, error) {
	return runSuite(ctx, m.BuilderContainer(src), goTestArgs(race), []string{"./..."}, true)
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
