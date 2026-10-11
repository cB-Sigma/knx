# Changelog

## v0.2.0 (2026-10-11)

Added:

- KNX IP Secure routing (`RoutingOptions.Secure`): wrapped frames under
  the backbone key, timer synchronisation as time keeper or follower
  (`TimerNotify`), latency tolerance; plain frames discarded.
- KNX Data Secure (`DataSecure`, `SealData`, `OpenData`): group keys,
  encryption and authentication-only, per-sender sequence numbers; on
  tunnels (`TunnelOptions.DataSecure`) and routing
  (`RoutingOptions.DataSecure`); `Keyring.DataSecure`.
- Routing flow control: ROUTING_BUSY pauses `Router.Send` with the
  randomised back-off, ROUTING_LOST_MESSAGE reported (`OnBusy`,
  `OnLostMessage`, `Router.Busy`), 20ms pacing (`MinInterval`),
  `SendBusy` and `SendLostMessage` for routers.
- Extended search (`SearchExtended`, search parameter blocks, secured
  families, tunnelling information and extended device information DIBs,
  `Description.Matches`).
- Busmonitor and raw tunnels (`TunnelOptions.Layer`, `OnBusmon`,
  `OnCEMI`, `ParseBusmon`).
- Management services on individual addresses (`IndividualFrame`,
  `ControlFrame`, APCI and TPCI constants), ten-bit APCIs decoded, frames
  longer than 15 octets sent as extended frames.
- DPTs 2.x, 3.x, 4.x, every 5.x, 6.x, 8.x, 10.001, 11.001, 12.x, 17.001,
  18.001, 19.001, 21.x, 29.x, 232.600, 251.600 (`DecodedDPTs`).
- ETS projects: DPTs and flags from the product catalogue (application
  program group objects) and from the object size; a group address takes
  its linked objects' DPT when they agree.
- Keyrings: backbone key, latency and multicast address, Data Secure
  group keys, interface groups and senders, device tool keys and
  sequence numbers (`SealKeyringKey` for simulators).
- Interop: routing with xknx 3.20.0 (plain, secure as keeper and as
  follower, Data Secure); keyring backbone and group keys compared with
  xknx on six keyrings; DPTs compared with xknxproject on nine projects.

Changed:

- DPT 7.003 and 7.004 decode to milliseconds (the raw value times 10 or
  100), matching their unit; they decoded the raw count before.
- `ParseConnectRequest` accepts the raw and busmonitor layers and returns
  the layer; `ParseLData` keeps the whole TPCI octet of control frames.
- A secure router ignores its own datagrams looped back by the group.

## v0.1.0 (2026-10-11)

First published release: KNXnet/IP search, description, tunnelling over
UDP and TCP, KNX IP Secure tunnelling, routing, cEMI group frames, DPTs,
ETS project and keyring import.

The simulated gateway and the tests that drive it are in the separate
module knx-sim. Interop tests against knxd 0.14.54.1, xknx 3.20.0 and
xknxproject 3.10.0 are in the nested module `interop`.
