# knx

A KNXnet/IP client in pure Go, with KNX IP Secure tunnelling and import of ETS projects and keyrings.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/knx.svg)](https://pkg.go.dev/github.com/cB-Sigma/knx) [![test](https://github.com/cB-Sigma/knx/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/knx/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

It tunnels over UDP and TCP, runs KNX IP Secure sessions, sends and
receives over multicast routing, searches for gateways, encodes and
decodes cEMI group frames and datapoint types, and reads the files a KNX
installer hands over: the ETS project export (.knxproj, password-protected
or not, ETS 4 to 6) and the ETS keyring (.knxkeys). It uses only the
standard library, without cgo. It was written for SigmaM2M, a oneM2M
platform, where it serves the KNX integration.

## Features

| Feature | Status |
|---|---|
| Search and description, multicast or unicast | yes |
| Tunnelling, link layer, over UDP: sequence counters, acknowledgement with one repeat, repeated requests delivered once, heartbeat, NAT mode | yes |
| Tunnelling over TCP (KNXnet/IP core v2) | yes |
| KNX IP Secure tunnelling: session handshake, device authentication check, user authentication, secure wrapper with sequence and MAC checks, keepalive | yes |
| Routing over multicast (or to a unicast peer) | yes, without flow control (ROUTING_BUSY) or lost-message handling |
| KNX IP Secure routing | no |
| KNX Data Secure (group keys) | no; a keyring's group keys are counted and reported |
| Extended search (SEARCH_REQUEST_EXTENDED) as a client | no |
| cEMI L_Data with group value read, response and write | yes; other application services are not decoded |
| Device management, busmonitor and raw tunnelling layers; USB and serial interfaces | no |
| DPTs decoded | 1.x, 5.001, 5.003, 5.004, 5.010, 7.x, 9.x, 13.x, 14.x, 16.000, 16.001, 20.x; any other well-formed DPT as raw hex (`ErrDPTRaw`) |
| ETS project import (.knxproj, bare 0.xml) | group addresses with names, DPTs and group ranges; group object read/write flags from 0.xml; ETS 4/5 (ZipCrypto) and ETS 6 (WinZip AES) protection |
| DPTs that a project gives only on the device's group objects (in the product catalogue files) | no: such group addresses come without a DPT (see "Interop tested against") |
| ETS keyring import (.knxkeys) | signature check, tunnelling interfaces, device authentication and management passwords |

## Choosing a KNX library

Compared from each project's source at the versions named, in October
2026. "Tested" means run against this module in the interop tests below.
Check the projects themselves before relying on a row.

| | this module | knx-go (commit 02e5353) | xknx 3.20.0 + xknxproject 3.10.0 | knxd 0.14.54.1 |
|---|---|---|---|---|
| Language | Go, no cgo | Go | Python (asyncio) | C++ daemon, used through its socket or KNXnet/IP |
| Licence | Apache-2.0 | MIT | MIT; xknxproject GPL-2.0-only | GPL-2.0 |
| Tunnelling over UDP | yes (tested against knxd) | yes, data, raw and busmonitor layers | yes | server and client |
| Tunnelling over TCP | yes | no | yes | no |
| KNX IP Secure tunnelling | yes | no | yes | no |
| KNX IP Secure routing, KNX Data Secure | no | no | yes | no |
| Routing flow control (ROUTING_BUSY, ROUTING_LOST) | no | yes | yes | yes |
| Datapoint types decoded | 12 families (see above) | 19 main types | the widest set (34 modules in xknx/dpt) | none (raw) |
| ETS keyring | yes (tested: same results as xknx on five ETS keyrings) | no | yes | no |
| ETS project | group addresses, ranges, flags (tested: same addresses and names as xknxproject on nine ETS projects) | no | xknxproject: also topology, devices, functions, DPTs from the product catalogue | no |
| Simulated gateway for tests | yes ([knx-sim](https://github.com/cB-Sigma/knx-sim), tested with xknx) | no | no | can be configured as one |

Pick this module for a Go program that needs KNX IP Secure, TCP
tunnelling or ETS import, or a gateway simulator to test against. Pick
knx-go for plain UDP tunnelling or routing in Go when you want its wider
set of DPTs and busmonitor access, or routing with flow control. Pick
xknx (with xknxproject) in Python, or when you need Secure routing, Data
Secure, more DPTs or the full ETS project model; this module does not
have them yet. knxd is a daemon rather than a library: pick it to share
one bus interface (USB, serial, IP) among several programs.

## Install

```
go get github.com/cB-Sigma/knx@latest
```

Requires Go 1.24.0 or later.

## Quick start

```go
import "github.com/cB-Sigma/knx"

found, _ := knx.Search(ctx, "", 3*time.Second) // multicast search
tn, err := knx.DialTunnel(ctx, found[0].Control.Addr.String(), knx.TunnelOptions{
	OnFrame: func(f knx.LData) { /* indications and confirmations */ },
})
light, _ := knx.ParseGroupAddress("1/1/7")
err = tn.Send(ctx, knx.GroupFrame(knx.LDataReq, light, knx.GroupValueWrite, []byte{1}, true))
```

For KNX IP Secure, take the credentials from the ETS keyring:

```go
k, _ := knx.ParseKeyring(keyringBytes, keyringPassword)
in, deviceAuth, _ := k.Tunnel("", 0)
tn, err := knx.DialTunnel(ctx, "192.168.1.20:3671", knx.TunnelOptions{Secure: &knx.SecureOptions{
	UserID: byte(in.UserID), PasswordHash: knx.UserPasswordHash(in.Password),
	DeviceAuth: knx.DeviceAuthCode(deviceAuth)}})
```

The runnable examples here are `ExampleParseDPT`,
`ExampleParseGroupAddress` and `ExampleParseETSProject`; knx-sim has a
tunnel against the simulated gateway and a protected ETS 6 export with
its keyring.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/knx

| Package | What it does |
|---|---|
| `knx` (module root) | KNXnet/IP frames; `DialTunnel` (UDP, TCP, KNX IP Secure), `ListenRouting`, `Search`; cEMI `LData`, `GroupFrame`, group and individual addresses; `DPT` encode and decode; `ParseETSProject`, `ETSPoints`, `ParseKeyring` |
| `interop` (nested module, tests only) | this module against knxd, xknx and xknxproject in Docker |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.
The tests that drive the simulated gateway are in
[knx-sim](https://github.com/cB-Sigma/knx-sim), so this module does not
depend on its simulator.

`interop/` is a nested module with its own go.mod. It runs knxd from
Debian bookworm and xknx and xknxproject from PyPI in containers
(`interop/peer`, `interop/xknx`). It is skipped unless
`SIGMA_KNX_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_KNX_INTEROP=1 go test -v ./...
```

### Interop tested against

On 2026-10-11, Docker Desktop 29.4.3 on arm64:

- knxd 0.14.54.1 (GPL-2.0) as a KNXnet/IP tunnelling server, reached
  through a container port in NAT mode: two tunnels of this module got
  their own addresses from knxd and its description; group writes (short
  and long), a group read and the response to it passed from one tunnel
  to the other and to knxtool on knxd's bus, each confirmed by knxd;
  writes and a read sent with knxtool reached both tunnels. All passed.
  Search was not run: knxd answers to the endpoint in the request, which
  a container's port mapping makes unreachable.
- ETS keyrings: the five keyrings of xknx 3.20.0's test suite that have
  known passwords (written by ETS, with backbone keys, group keys, USB
  and IP interfaces, special characters in passwords) read with the same
  interfaces, user IDs, passwords, authentication codes, devices,
  management passwords and group key counts as xknx reads them, and
  `Keyring.Tunnel` gives the credentials xknx uses for each secure
  tunnel. A wrong password was refused for each. All passed.
- ETS projects: the nine projects of xknxproject 3.10.0's test suite
  (ETS 4, 5 and 6; plain and protected) read with the same group
  addresses and names as xknxproject reads them, and the same DPT
  wherever this module has one. Thirteen group addresses in four projects
  have a DPT only on the linked group objects, from the product
  catalogue, which xknxproject reads and this module does not; they come
  without a DPT here.
- The KNX IP Secure primitives reproduce xknx's published example values
  (secure_test.go). The secure tunnel of this module has been run only
  against knx-sim, whose secure gateway xknx 3.20.0 connected to (see
  knx-sim).
- Not yet: a real KNX IP interface or router, routing between two
  implementations, Calimero.

## Related repositories

- [knx-sim](https://github.com/cB-Sigma/knx-sim): a simulated KNXnet/IP
  gateway (UDP, TCP, KNX IP Secure) and ETS file generators, as a Go
  package and a command.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. KNX and ETS are trademarks of the KNX Association; this
project is not affiliated with or endorsed by it.
