# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, from the KNX descriptions
and the zip format documents below. No code was ported or copied from
another implementation. Where the KNX documents are published to KNX
Association members only (KNX IP Secure, the ETS keyring, the ETS project
schema), the facts were read from two Python projects, xknx (MIT) and
xknxproject (GPL-2.0-only). The table names the files read and what was
taken from each. Facts are not code: service type numbers, frame
layouts, salts, iteration counts and element names are what every
implementation must use, and our code around them is our own design (Go
types, goroutine and channel connections, our own error handling). No
specification text is reproduced; comments cite volume, part and clause
numbers in our own words.

The KNXnet/IP core, tunnelling, routing, cEMI and DPT code came with
SigmaM2M's baseline (2026-09-27); its comments cite the KNX Standard
v2.1, and no other source is recorded for it. KNX IP Secure tunnelling
and TCP were added on 2026-10-05, and ETS import the same day. The
module became a module of its own on 2026-10-06. On 2026-10-11 the
simulated gateway, its command and the tests that drive it moved to the
separate module knx-sim (with `git mv`), so this module does not depend
on its simulator, and the interop tests against knxd, xknx and
xknxproject (interop/) were added.

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| KNXnet/IP frames, search, description, tunnelling, routing (frame.go, tunnel.go, routing.go) | KNX Standard v2.1, volume 3 part 8 (KNXnet/IP; ISO 22510): core (header, HPAI, DIBs, search, description, connection state), device management, tunnelling (connection, sequence counters, acknowledgement and one repeat), routing (indications over multicast) | none recorded |
| KNXnet/IP over TCP (transport.go) | KNX Standard v2.1 volume 3 part 8, core v2: the TCP host protocol code, stream framing by total length, route-back endpoints, no tunnelling acknowledgement | none recorded |
| KNX IP Secure tunnelling (secure.go, transport.go) | KNX Standard v2.1 volume 3 part 8 chapter 9 (KNXnet/IP Secure), as summarised publicly | xknx (MIT): xknx/secure/security_primitives.py and examples/ip_secure_calculations.py: the X25519 session key, the PBKDF2 salts and iteration count for the user password hash and the device authentication code, the session response and authenticate MACs, the secure wrapper's CCM block layout and counter blocks |
| cEMI and group services (cemi.go) | KNX Standard v2.1 volume 3 part 6 (cEMI L_Data) and part 3 (application layer group value services; group and individual address formats) | none recorded |
| Datapoint types (dpt.go) | KNX Standard v2.1 volume 3 part 7 section 2 (the encodings of DPT 1, 5, 7, 9, 13, 14, 16 and 20; the two-byte float; which types travel in the APCI octet) | none recorded |
| ETS keyring (.knxkeys) (keyring.go) | none public | xknx (MIT): xknx/secure/keyring.py: the PBKDF2 parameters and salt of the keyring key, the IV from the Created attribute, the 8 filler bytes and padding around a password, and the signature's serialisation of the document |
| ETS project (.knxproj) (ets.go) | the KNX XML project schema (KNX Association) | xknxproject (GPL-2.0-only): xknxproject/zip/extractor.py and loader/project_loader.py: the archive layout (P-xxxx folder, signature entry, inner P-xxxx.zip when protected), the ETS 6 project password derivation parameters, and the names of the 0.xml elements and attributes for group ranges, group addresses, datapoint types and group object links |
| Protected project zips (etszip.go) | PKWARE APPNOTE section 6.1 (traditional "ZipCrypto" encryption); WinZip "AES Encryption Information" (AE-1/AE-2, extra field 0x9901, PBKDF2-HMAC-SHA1 keys, little-endian CTR, HMAC-SHA1 authentication) | none |
| Interop peers (interop/) | knxd's command-line and knxtool usage; xknx's and xknxproject's public APIs, read to write interop/xknx/peer.py | the peers run in containers built from their own releases |

An earlier review in SigmaM2M compared this module's tunnelling
behaviour with knxd and xknx; that was a comparison of behaviour, not a
source. Calimero (Java, GPL-2.0 with classpath exception), knxd (C,
GPL-2.0) and knx-go (Go, MIT) are not recorded as having been read for
this code, and no identifier, comment or porting marker of theirs, of
xknx or of xknxproject appears in it. The owner decided on 2026-10-06
that no line-by-line comparison with the projects read is needed; these
notes are the record. xknxproject's licence (GPL-2.0-only) is noted here
because an earlier version of these notes called it MIT: only facts were
taken from it, which its licence does not cover.

## Test vectors and where they come from

| Test | Source |
|---|---|
| secure_test.go (TestKNXSecureVectors) | the example values of xknx's examples/ip_secure_calculations.py: the passwords "trustme" and "secret" and their derived keys, the X25519 keys, the SESSION_RESPONSE MAC, the SESSION_AUTHENTICATE frame, and the wrapped SESSION_AUTHENTICATE and SESSION_STATUS frames |
| codec_test.go | frames and encodings worked from the KNX Standard clauses each test names |
| example_test.go | a hand-written 0.xml and demo values |
| interop/ets_test.go | keyrings and projects written by ETS, from the test suites of xknx 3.20.0 and xknxproject 3.10.0, fetched when the test image is built; xknx and xknxproject read the same files for comparison |
| interop/knxd_test.go | knxd 0.14.54.1 and knxtool as the gateway and another bus device |

The tests that drive the simulated gateway (tunnelling, KNX IP Secure,
ETS import of generated files) are in knx-sim.

All passwords, keys and addresses other than the xknx example values are
made-up demo values.
