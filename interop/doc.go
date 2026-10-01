// SPDX-License-Identifier: AGPL-3.0-only

// Package interop checks the softpsp PSP codec against the reference code in
// github.com/google/psp. The CI Interop lane builds the reference and runs it
// in both directions (TestReference). testdata/vectors.json keeps the result,
// so go test also checks it without the C code (TestVectors).
package interop
