// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
)

// secureTestKeyring is the part of xknx 3.20.0's test keyring
// test/secure_tests/resources/SecureTest.knxkeys (written by ETS, password
// "test") that the Data Secure vectors need, without its signature.
const secureTestKeyring = `<?xml version="1.0" encoding="utf-8"?>
<Keyring Project="SecureTest" Created="2023-01-30T19:17:06" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.13" Latency="1000" Key="JxjdynGrSOB+9XV9NBaNxQ==" />
  <Interface IndividualAddress="5.0.1" Type="Tunneling" Host="5.0.0" UserID="2">
    <Group Address="1028" Senders="4.0.9" />
    <Group Address="1027" Senders="4.0.9" />
    <Group Address="1024" Senders="4.0.1 4.0.9" />
  </Interface>
  <GroupAddresses>
    <Group Address="1024" Key="B8nWiBBMs/wH3I3aYKmHlw==" />
    <Group Address="1027" Key="uoumUsZz3bG4yIu1PsBODQ==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="4.0.9" ToolKey="Ov+HnCVh/87jokTrsRnlfw==" SequenceNumber="155806854915" />
  </Devices>
</Keyring>`

func testDataSecure(t *testing.T, seq uint64) (*knx.Keyring, *knx.DataSecure) {
	t.Helper()
	k, err := knx.ParseKeyring([]byte(secureTestKeyring), "test")
	if err != nil {
		t.Fatal(err)
	}
	ds, err := k.DataSecure("")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 0 {
		ga, _ := knx.ParseGroupAddress("0/4/0")
		ds, err = knx.NewDataSecure(knx.DataSecureOptions{GroupKeys: map[knx.GroupAddress][]byte{ga: k.DataSecureKeys[ga]},
			Senders: k.DataSecureSenders(), Sequence: seq})
		if err != nil {
			t.Fatal(err)
		}
	}
	return k, ds
}

// The keyring's backbone key, latency, group keys, interface groups and
// device sequence numbers are read as xknx reads them.
// Covers: SIG-IPE-6706
func TestKeyringSecureMaterial(t *testing.T) {
	k, _ := testDataSecure(t, 0)
	if !k.Backbone || len(k.BackboneKey) != 16 || k.BackboneLatency != time.Second || k.BackboneMulticast != "224.0.23.13" {
		t.Errorf("backbone %v %x %v %q", k.Backbone, k.BackboneKey, k.BackboneLatency, k.BackboneMulticast)
	}
	if k.GroupKeys != 2 || len(k.DataSecureKeys) != 2 {
		t.Errorf("group keys %d %d", k.GroupKeys, len(k.DataSecureKeys))
	}
	s := k.DataSecureSenders()
	if s[0x4009] != 155806854915 || len(s) != 2 {
		t.Errorf("senders %v", s)
	}
	if len(k.Interfaces[0].Groups) != 3 {
		t.Errorf("interface groups %v", k.Interfaces[0].Groups)
	}
	if _, err := k.DataSecure("9.9.9"); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("unknown receiver: %v", err)
	}
	if ds, err := k.DataSecure("5.0.1"); err != nil || !ds.Secured(0x0400) || !ds.Secured(0x0403) || ds.Secured(0x0404) {
		t.Errorf("receiver 5.0.1: %v", err)
	}
}

// A secured GroupValue_Response from xknx's test suite opens to the plain
// value and raises the sender's sequence number; replaying it, changing
// its MAC or sending a plain frame to the secured group is refused.
// Covers: SIG-IPE-6701
func TestDataSecureReceiveVector(t *testing.T) {
	_, ds := testDataSecure(t, 0)
	raw, _ := hex.DecodeString("29003ce0400904001103f110002446cfef4ac085e7092ab062b44d")
	f, err := knx.ParseLData(raw)
	if err != nil || f.APCI != knx.SecureService {
		t.Fatalf("parse %+v %v", f, err)
	}
	p, err := ds.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.APCI != knx.GroupValueResponse || !bytes.Equal(p.Value(), []byte{116, 41, 41}) || p.Group().String() != "0/4/0" || p.Source.String() != "4.0.9" {
		t.Errorf("plain = %+v", p)
	}
	if s, _ := ds.LastSequence(0x4009); s != 155806854986 {
		t.Errorf("last sequence %d", s)
	}
	if _, err := ds.Open(f); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("replay: %v", err)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	fb, _ := knx.ParseLData(bad)
	_, ds2 := testDataSecure(t, 0)
	if _, err := ds2.Open(fb); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("altered MAC: %v", err)
	}
	plain := knx.GroupFrame(knx.LDataInd, 0x0400, knx.GroupValueResponse, []byte{1, 2, 3}, false)
	plain.Source = 0x4009
	if _, err := ds2.Open(plain); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("plain frame to a secured group: %v", err)
	}
	other := knx.GroupFrame(knx.LDataInd, 0x0A03, knx.GroupValueWrite, []byte{1}, true)
	if got, err := ds2.Open(other); err != nil || got.Short != 1 {
		t.Errorf("plain frame to an unsecured group: %v", err)
	}
	f.Source = 0x1203
	if _, err := ds2.Open(f); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("unknown sender: %v", err)
	}
}

// Sealing reproduces xknx's published frames: a GroupValue_Read in a
// standard frame and a three-octet write that needs an extended frame,
// and each opens again.
// Covers: SIG-IPE-6701
func TestDataSecureSendVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    knx.LData
		want string
	}{
		{"read", knx.GroupFrame(knx.LDataReq, 0x0400, knx.GroupValueRead, nil, true), "bce0500104000e03f11000254ae1cb67cd184afe5744"},
		{"extended write", knx.GroupFrame(knx.LDataReq, 0x0400, knx.GroupValueWrite, []byte{255, 0, 5}, false), "3ce0500104001103f11000254ae1cb67cd98e577b519be47bb"},
	} {
		_, ds := testDataSecure(t, 160170101607)
		tc.f.Source = 0x5001
		s, err := ds.Seal(tc.f)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(s.Encode()[2:]); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
		if ds.NextSequence() != 160170101608 {
			t.Errorf("%s: next sequence %d", tc.name, ds.NextSequence())
		}
		back, _ := knx.ParseLData(s.Encode())
		_, rx := testDataSecure(t, 0)
		p, err := rx.Open(back)
		if err == nil {
			t.Errorf("%s: 5.0.1 is not a sender of the keyring's devices yet was accepted", tc.name)
		}
		k, _ := knx.ParseKeyring([]byte(secureTestKeyring), "test")
		p, seq, err := knx.OpenData(k.DataSecureKeys[0x0400], back)
		if err != nil || seq != 160170101607 || p.APCI != tc.f.APCI || !bytes.Equal(p.Value(), tc.f.Value()) {
			t.Errorf("%s: open = %+v %d %v", tc.name, p, seq, err)
		}
	}
	// Authentication only: the APDU travels in clear and still verifies.
	k, _ := knx.ParseKeyring([]byte(secureTestKeyring), "test")
	f := knx.GroupFrame(knx.LDataInd, 0x0400, knx.GroupValueWrite, []byte{7}, true)
	f.Source = 0x4009
	s := knx.SealData(k.DataSecureKeys[0x0400], knx.SCFAuthOnly, 200000000000, f)
	if !bytes.Contains(s.Data, []byte{0x00, 0x87}) {
		t.Errorf("auth-only data % x does not carry the plain APDU", s.Data)
	}
	_, ds := testDataSecure(t, 0)
	if p, err := ds.Open(s); err != nil || p.Short != 7 || p.APCI != knx.GroupValueWrite {
		t.Errorf("auth-only open = %+v %v", p, err)
	}
	s.Data[len(s.Data)-6] ^= 1 // the clear APDU
	if _, err := ds.Open(s); !errors.Is(err, knx.ErrDataSecure) {
		t.Errorf("altered clear APDU: %v", err)
	}
}
