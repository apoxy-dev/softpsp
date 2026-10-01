// SPDX-License-Identifier: Apache-2.0
// Apoxy changed this file for softpsp.

package psp

// spiLowMask selects the SPI bits below the master key index.
const spiLowMask = uint32(0x7fffffff)

// MasterKeyIndex returns which master key (0 or 1) an SPI selects: per PSP, the
// most-significant bit of the SPI.
func MasterKeyIndex(spi uint32) int { return int(spi >> 31) }

// ReservedSPI reports whether spi is reserved (low 31 bits zero). PSP reserves
// the all-zero value in each master-key half.
func ReservedSPI(spi uint32) bool { return spi&spiLowMask == 0 }
