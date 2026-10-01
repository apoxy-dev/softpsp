# softpsp

softpsp is the SoftPSP data path for Apoxy VPC Tunnels v2. It does PSP
encryption and decryption in user space, and moves overlay packets through a
TUN (L3) device.

## Status

Early. The code comes from [apoxy-dev/icx](https://github.com/apoxy-dev/icx)
(with its history). The v2 PSP handler is not written yet. The API can change
without notice.

## Packages

| Package | Contents |
| --- | --- |
| `psp` | PSP tunnel-mode packet codec, key derivation (AES-CMAC KDF) and the SPI master key index. |
| `interop` | Checks of `psp` against the [google/psp](https://github.com/google/psp) reference code. |
| `engine` | Packet engine. Receive SA rows: SPI lookup, decryption, VNI, source, packet limit and replay checks. Receive queues: each SA has one owner queue, and other queues hand its packets to it. Transmit SAs. |
| `keys` | Receiver-created SAs: two master keys, offers, rekeys, revokes, and the transmit SAs of a sender. |
| `replay` | RFC 6479 anti-replay window on the 32-bit sequence number. |
| `vtep` | Datapath contract and drivers: `tun`, `netstack`, `afxdp`. |
| `forwarder` | AF_XDP forwarder between a physical NIC and a veth. |
| `filter` | XDP programs for the forwarder. |
| `queues`, `udp`, `veth`, `permissions`, `internal/xsk` | Helpers for the packages above. |

## Tests

```sh
go build ./...
go vet ./...
go test ./...
```

The `forwarder`, `internal/xsk` and `veth` tests need root with NET_ADMIN and a
kernel with AF_XDP. The CI Unit lane leaves them out, and the privileged
Integration lane runs them (see `ci/`).

The CI Interop lane (`dagger call interop --src=.`) builds the google/psp
reference code and checks the codec against it in both directions.
`interop/testdata/vectors.json` keeps the reference output, so `go test` checks
it without the C code.

## License

- New code is AGPL-3.0-only. See [LICENSE](LICENSE).
- Files copied from icx stay under Apache-2.0. See
  [LICENSE-APACHE](LICENSE-APACHE). These files start with
  `SPDX-License-Identifier: Apache-2.0`, and the files that Apoxy changed say so.
- `replay` is from WireGuard and keeps its MIT license header.
- The eBPF C sources in `filter/ebpf` keep their GPL-2.0 license headers.
