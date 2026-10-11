# knx

A KNXnet/IP client and router in pure Go, with KNX IP Secure, KNX Data Secure and import of ETS projects and keyrings.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/knx.svg)](https://pkg.go.dev/github.com/cB-Sigma/knx) [![test](https://github.com/cB-Sigma/knx/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/knx/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

It tunnels over UDP and TCP, runs KNX IP Secure sessions, routes over
multicast (plain or KNX IP Secure, with flow control), protects group
telegrams end to end with KNX Data Secure, searches for gateways (also
with the extended search), encodes and decodes cEMI frames for group
communication and device management, decodes 24 families of datapoint
types, and reads the files a KNX installer hands over: the ETS project
export (.knxproj, password-protected or not, ETS 4 to 6, with datapoint
types from the product catalogue) and the ETS keyring (.knxkeys, with
backbone and group keys). It uses only the standard library, without
cgo. It was written for SigmaM2M, a oneM2M platform, where it serves the
KNX integration.

## Features

| Feature | Status |
|---|---|
| Search and description, multicast or unicast | yes |
| Extended search (SEARCH_REQUEST_EXTENDED) with search parameter blocks (programming mode, MAC, service family, requested DIBs); secured families, tunnelling slots and extended device information read | yes (`SearchExtended`, v0.2.0) |
| Tunnelling, link layer, over UDP: sequence counters, acknowledgement with one repeat, repeated requests delivered once, heartbeat, NAT mode | yes |
| Tunnelling over TCP (KNXnet/IP core v2) | yes |
| Busmonitor and raw tunnelling layers | yes (`TunnelOptions.Layer`, `OnBusmon`, `OnCEMI`, v0.2.0) |
| KNX IP Secure tunnelling: session handshake, device authentication check, user authentication, secure wrapper with sequence and MAC checks, keepalive | yes |
| Routing over multicast (or to a unicast peer) | yes |
| Routing flow control: ROUTING_BUSY pauses sending (with the randomised back-off for repeated busy frames), ROUTING_LOST_MESSAGE reported, 20ms pacing; sending busy and lost frames | yes (v0.2.0) |
| KNX IP Secure routing: backbone key, wrapped frames, timer synchronisation (time keeper and follower, TIMER_NOTIFY, latency tolerance) | yes (`RoutingOptions.Secure`, v0.2.0) |
| KNX Data Secure: S-A_Data with group keys, CCM encryption and authentication-only, per-sender sequence numbers, plain frames to secured groups refused; on tunnels and routing | yes (`DataSecure`, v0.2.0); point-to-point frames with a tool key and the sync services are refused, not handled |
| cEMI L_Data: group value services; management services on individual addresses (descriptor, property, memory, address, ADC, restart, authorise, key, function property, domain address); transport control frames; extended frames; L_Busmon.ind | yes (v0.2.0); connection-oriented management sessions (T_Connect with numbered data and acks) are built from these frames by the caller |
| USB and serial interfaces, cEMI device management connections (DEVICE_CONFIGURATION_REQUEST) | no |
| DPTs decoded | 1.x, 2.x, 3.x, 4.x, 5.x, 6.x, 7.x, 8.x, 9.x, 10.001, 11.001, 12.x, 13.x, 14.x, 16.000, 16.001, 17.001, 18.001, 19.001, 20.x, 21.x, 29.x, 232.600, 251.600; any other well-formed DPT as raw hex (`ErrDPTRaw`) |
| ETS project import (.knxproj, bare 0.xml) | group addresses with names, DPTs and group ranges; DPTs and read/write flags from 0.xml, else from the product catalogue (application program group objects, object size); ETS 4/5 (ZipCrypto) and ETS 6 (WinZip AES) protection |
| ETS project topology, devices, functions, parameters | no |
| ETS keyring import (.knxkeys) | signature check, tunnelling interfaces with their secured groups and senders, device authentication and management passwords, tool keys, sequence numbers, backbone key, Data Secure group keys |

## Choosing a KNX library

Compared from each project's source at the versions named, in October
2026. "Tested" means run against this module in the interop tests below.
Check the projects themselves before relying on a row.

| | this module | knx-go (commit 02e5353) | xknx 3.20.0 + xknxproject 3.10.0 | knxd 0.14.54.1 |
|---|---|---|---|---|
| Language | Go, no cgo | Go | Python (asyncio) | C++ daemon, used through its socket or KNXnet/IP |
| Licence | Apache-2.0 | MIT | MIT; xknxproject GPL-2.0-only | GPL-2.0 |
| Tunnelling over UDP | yes (tested against knxd) | yes | yes | server and client |
| Busmonitor and raw tunnels | yes | yes | no | busmonitor |
| Tunnelling over TCP | yes | no | yes | no |
| KNX IP Secure tunnelling | yes | no | yes | no |
| KNX IP Secure routing | yes (tested with xknx, both as time keeper and follower) | no | yes | no |
| KNX Data Secure | yes, group keys (tested with xknx over routing and with xknx's published frames) | no | yes, group keys | no |
| Routing flow control (ROUTING_BUSY, ROUTING_LOST) | yes | yes | yes | yes |
| Extended search | yes | no | yes | not checked |
| Device management | frames only | not checked | yes: connection-oriented sessions, property and memory services, individual address programming | not checked |
| Datapoint types decoded | 24 families (see above) | 19 main types | the widest set (34 modules in xknx/dpt) | none (raw) |
| ETS keyring | yes (tested: same results as xknx on six ETS keyrings, including backbone and group keys) | no | yes | no |
| ETS project | group addresses, ranges, DPTs (also from the catalogue), flags (tested: same addresses, names and DPTs as xknxproject on nine ETS projects) | no | xknxproject: also topology, devices, functions, parameters | no |
| Simulated gateway and router for tests | yes ([knx-sim](https://github.com/cB-Sigma/knx-sim), tested with xknx) | no | no | can be configured as one |

Pick this module for a Go program that needs KNX IP Secure (tunnelling or
routing), KNX Data Secure, TCP tunnelling or ETS import, or a gateway or
router simulator to test against. Pick knx-go when you already use it for
plain tunnelling or routing in Go. Pick xknx (with xknxproject) in
Python, when you need connection-oriented device management (programming
individual addresses, reading memory in a session), the widest DPT set,
or the full ETS project model (topology, devices, functions); this module
has the frames for management but not the session logic. knxd is a
daemon rather than a library: pick it to share one bus interface (USB,
serial, IP) among several programs.

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

Secure routing with KNX Data Secure, from the same keyring:

```go
ds, _ := k.DataSecure("")
r, err := knx.ListenRouting(knx.RoutingOptions{Group: k.BackboneMulticast + ":3671", DataSecure: ds,
	Secure: &knx.SecureRoutingOptions{BackboneKey: k.BackboneKey, Latency: k.BackboneLatency},
	OnFrame: func(f knx.LData) { /* opened frames */ }})
```

The runnable examples here are `ExampleParseDPT`,
`ExampleParseGroupAddress` and `ExampleParseETSProject`; knx-sim has a
tunnel against the simulated gateway and a protected ETS 6 export with
its keyring.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/knx

| Package | What it does |
|---|---|
| `knx` (module root) | KNXnet/IP frames; `DialTunnel` (UDP, TCP, KNX IP Secure; link, raw and busmonitor layers), `ListenRouting` (flow control, KNX IP Secure), `Search`, `SearchExtended`; cEMI `LData`, `GroupFrame`, `IndividualFrame`, `ControlFrame`, `ParseBusmon`; `DataSecure`, `SealData`, `OpenData`; `TimerNotify`; `DPT` encode and decode; `ParseETSProject`, `ETSPoints`, `ParseKeyring` |
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
- xknx 3.20.0 as a router (v0.2.0): this module's router (`interop/routepeer`,
  built for Linux) and xknx on one multicast group inside one container,
  with the keyring SecureTest.knxkeys of xknx's test suite. Plain
  routing, KNX IP Secure routing with this module as time keeper, and
  KNX IP Secure routing started after xknx so that this module follows
  xknx's time; in each, with KNX Data Secure for the keyring's secured
  groups. Each side received the other's plain and Data Secure group
  writes, and xknx read a value this module answered. All passed.
- ETS keyrings: the six keyrings of xknx 3.20.0's test suite that have
  known passwords (written by ETS, with backbone keys, group keys, USB
  and IP interfaces, special characters in passwords) read with the same
  interfaces, user IDs, passwords, authentication codes, devices,
  management passwords, backbone key, latency and multicast address,
  Data Secure group keys and senders with sequence numbers as xknx reads
  them, and `Keyring.Tunnel` gives the credentials xknx uses for each
  secure tunnel. A wrong password was refused for each. All passed.
- ETS projects: the nine projects of xknxproject 3.10.0's test suite
  (ETS 4, 5 and 6; plain and protected) read with the same group
  addresses, names and DPTs as xknxproject reads them, including the
  thirteen group addresses whose DPT comes only from the linked group
  objects in the product catalogue or from their object size (v0.2.0).
  All passed.
- The KNX IP Secure primitives reproduce xknx's published example values
  (secure_test.go), the TIMER_NOTIFY MACs those of xknx's secure group
  tests, and KNX Data Secure the frames of xknx's Data Secure tests
  (routing_test.go, datasecure_test.go). The secure tunnel of this module
  has been run against knx-sim, whose secure gateway xknx 3.20.0
  connected to (see knx-sim).
- Not yet: a real KNX IP interface or router, Calimero.

## Related repositories

- [knx-sim](https://github.com/cB-Sigma/knx-sim): a simulated KNXnet/IP
  gateway (UDP, TCP, KNX IP Secure, KNX Data Secure, busmonitor, device
  management) and router (plain or secure, flow control), and ETS file
  generators, as a Go package and a command.

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
