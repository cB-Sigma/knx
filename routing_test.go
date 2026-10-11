// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
)

// TIMER_NOTIFY MACs reproduce the values of xknx 3.20.0's secure group
// tests (test/io_tests/secure_group_test.py), and an altered one fails.
// Covers: SIG-IPE-6702
func TestTimerNotifyVectors(t *testing.T) {
	key, _ := hex.DecodeString("0aa227b4fd7a32319ba9960ac036ce0e5c4507b5ae55161f1078b1dcfb3cb631")
	serial := [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78}
	for _, tc := range []struct {
		timer uint64
		mac   string
	}{
		{0, "3195051bb981941d57e6c5b55355f341"},
		{60 * 60 * 1000, "d2fad5657a5788a36cdd8a3ef84c90ab"},
	} {
		n := knx.TimerNotify{Timer: tc.timer, Serial: serial, Tag: [2]byte{0x12, 0x34}}.Sealed(key)
		if hex.EncodeToString(n.MAC) != tc.mac {
			t.Errorf("timer %d MAC %x, want %s", tc.timer, n.MAC, tc.mac)
		}
		back, err := knx.ParseTimerNotify(n.Frame().Body)
		if err != nil || !back.Verify(key) || back.Timer != tc.timer || back.Serial != serial {
			t.Errorf("parse %+v %v", back, err)
		}
		back.Timer++
		if back.Verify(key) {
			t.Error("an altered timer verified")
		}
	}
}

func udpPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

type frames struct {
	mu sync.Mutex
	fs []knx.LData
}

func (f *frames) add(x knx.LData) { f.mu.Lock(); f.fs = append(f.fs, x); f.mu.Unlock() }
func (f *frames) wait(t *testing.T, n int) []knx.LData {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		got := append([]knx.LData(nil), f.fs...)
		f.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d frames, want %d", len(got), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A pair of routers on unicast addresses (multicast is not needed to test
// the protocol).
func routerPair(t *testing.T, a, b knx.RoutingOptions) (*knx.Router, *knx.Router) {
	t.Helper()
	pa, pb := udpPort(t), udpPort(t)
	a.Group, a.Listen = pb, pa
	b.Group, b.Listen = pa, pb
	// One after the other: a secure router synchronises its timer first.
	ra, errA := knx.ListenRouting(a)
	rb, errB := knx.ListenRouting(b)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	t.Cleanup(ra.Close)
	t.Cleanup(rb.Close)
	return ra, rb
}

// ROUTING_BUSY pauses the sender for its wait time; ROUTING_LOST_MESSAGE
// is reported; indications are paced by the least interval.
// Covers: SIG-IPE-6703
func TestRoutingFlowControl(t *testing.T) {
	var got frames
	var lost []knx.RoutingLostMessage
	var mu sync.Mutex
	ra, rb := routerPair(t, knx.RoutingOptions{MinInterval: 30 * time.Millisecond, OnLostMessage: func(l knx.RoutingLostMessage) {
		mu.Lock()
		lost = append(lost, l)
		mu.Unlock()
	}}, knx.RoutingOptions{OnFrame: got.add})
	ga, _ := knx.ParseGroupAddress("1/1/1")
	ctx := context.Background()
	start := time.Now()
	for i := range 3 {
		if err := ra.Send(ctx, knx.GroupFrame(0, ga, knx.GroupValueWrite, []byte{byte(i)}, true)); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 55*time.Millisecond {
		t.Errorf("three indications left within %v; want them 30ms apart", d)
	}
	got.wait(t, 3)
	if err := rb.SendBusy(300 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := rb.SendLostMessage(4); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, l := ra.Busy(); b == 1 && l == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("busy and lost message not seen")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start = time.Now()
	if err := ra.Send(ctx, knx.GroupFrame(0, ga, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Errorf("sent %v after ROUTING_BUSY(300ms)", d)
	}
	got.wait(t, 4)
	mu.Lock()
	if len(lost) != 1 || lost[0].Lost != 4 {
		t.Errorf("lost messages %v", lost)
	}
	mu.Unlock()
	// A context ending during the pause stops the send.
	_ = rb.SendBusy(2 * time.Second)
	time.Sleep(50 * time.Millisecond)
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := ra.Send(cctx, knx.GroupFrame(0, ga, knx.GroupValueWrite, []byte{1}, true)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("send during busy pause: %v", err)
	}
}

// Two routers on a secure backbone synchronise their timers (the first
// becomes time keeper, the second adopts its time), exchange wrapped
// indications, and discard plain ones and wrappers under another key; a
// KNX Data Secure frame passes end to end through them.
// Covers: SIG-IPE-6702
func TestSecureRouting(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 16)
	k, _ := knx.ParseKeyring([]byte(secureTestKeyring), "test")
	dsA, _ := knx.NewDataSecure(knx.DataSecureOptions{GroupKeys: k.DataSecureKeys, Sequence: 1000})
	dsB, _ := knx.NewDataSecure(knx.DataSecureOptions{GroupKeys: k.DataSecureKeys, Senders: map[knx.IndividualAddress]uint64{0x1101: 0}})
	var got frames
	var errs []error
	var mu sync.Mutex
	ra, rb := routerPair(t,
		knx.RoutingOptions{Source: 0x1101, DataSecure: dsA, Secure: &knx.SecureRoutingOptions{BackboneKey: key, Latency: 100 * time.Millisecond, Serial: [6]byte{1}}},
		knx.RoutingOptions{OnFrame: got.add, DataSecure: dsB, OnError: func(e error) { mu.Lock(); errs = append(errs, e); mu.Unlock() },
			Secure: &knx.SecureRoutingOptions{BackboneKey: key, Latency: 100 * time.Millisecond, Serial: [6]byte{2}}})
	if !ra.TimeKeeper() || rb.TimeKeeper() {
		t.Errorf("time keepers: a %v b %v", ra.TimeKeeper(), rb.TimeKeeper())
	}
	ctx := context.Background()
	plainGA, _ := knx.ParseGroupAddress("1/1/1")
	if err := ra.Send(ctx, knx.GroupFrame(0, plainGA, knx.GroupValueWrite, []byte{1}, true)); err != nil {
		t.Fatal(err)
	}
	if err := ra.Send(ctx, knx.GroupFrame(0, 0x0400, knx.GroupValueWrite, []byte{0x0C, 0x1A}, false)); err != nil {
		t.Fatal(err)
	}
	fs := got.wait(t, 2)
	if fs[0].Group() != plainGA || fs[0].Short != 1 {
		t.Errorf("first = %+v", fs[0])
	}
	if fs[1].Group() != 0x0400 || fs[1].APCI != knx.GroupValueWrite || !bytes.Equal(fs[1].Value(), []byte{0x0C, 0x1A}) {
		t.Errorf("data secure frame = %+v", fs[1])
	}
	// A plain indication and a wrapper under another key are dropped.
	c, _ := net.DialUDP("udp4", nil, rb.LocalAddr())
	defer c.Close()
	_, _ = c.Write(knx.RoutingIndication(knx.GroupFrame(knx.LDataInd, plainGA, knx.GroupValueWrite, []byte{0}, true).Encode()).Encode())
	w := knx.SecureWrapper{Seq: 1 << 40, Serial: [6]byte{9}}.Wrap(bytes.Repeat([]byte{1}, 16),
		knx.RoutingIndication(knx.GroupFrame(knx.LDataInd, plainGA, knx.GroupValueWrite, []byte{0}, true).Encode()))
	_, _ = c.Write(w.Encode())
	time.Sleep(200 * time.Millisecond)
	if n := len(got.wait(t, 2)); n != 2 {
		t.Errorf("%d frames after a plain and a foreign frame", n)
	}
	mu.Lock()
	if len(errs) == 0 || !errors.Is(errs[0], knx.ErrSecure) {
		t.Errorf("errors %v", errs)
	}
	mu.Unlock()
}

// Extended search parameter blocks round-trip and select gateways; the
// extended response's secured families, tunnelling slots and extended
// device information are read back.
// Covers: SIG-IPE-6704
func TestSearchExtendedFrames(t *testing.T) {
	h := knx.HPAI{}
	f := knx.SearchRequestExtended(h, knx.SRPByService(knx.FamilyTunnelling, 2), knx.SRPWantDIBs(knx.DIBTunnellingInfo))
	if f.Service != knx.SvcSearchRequestExtended {
		t.Fatal(f.Service)
	}
	_, srps, err := knx.ParseSearchRequestExtended(f.Body)
	if err != nil || len(srps) != 2 || !srps[0].Mandatory || srps[1].Mandatory || !bytes.Equal(srps[1].Data, []byte{knx.DIBTunnellingInfo, 0}) {
		t.Fatalf("srps %+v %v", srps, err)
	}
	d := knx.Description{Device: knx.DeviceInfo{MAC: [6]byte{1, 2, 3, 4, 5, 6}, FriendlyName: "gw"},
		Families:        []knx.Family{{ID: knx.FamilyCore, Version: 2}, {ID: knx.FamilyTunnelling, Version: 2}},
		SecuredFamilies: []knx.Family{{ID: knx.FamilyTunnelling, Version: 1}},
		Tunnels:         &knx.TunnellingInfo{MaxAPDU: 248, Slots: []knx.TunnelSlot{{Address: 0x11F1, Usable: true, Free: true}, {Address: 0x11F2, Usable: true, Authorised: true}}},
		Extended:        &knx.ExtendedDeviceInfo{MediumStatus: 1, MaxLocalAPDU: 254, DeviceDescriptor: 0x091A}}
	if !d.Matches(srps) || d.Matches([]knx.SRP{knx.SRPByProgrammingMode()}) || !d.Matches([]knx.SRP{knx.SRPByMAC([6]byte{1, 2, 3, 4, 5, 6})}) ||
		d.Matches([]knx.SRP{knx.SRPByService(knx.FamilyRouting, 1)}) || d.Matches([]knx.SRP{{Type: 0x7E, Mandatory: true}}) {
		t.Error("search parameter matching")
	}
	back, err := knx.ParseSearchResponse(d.SearchResponseExtendedFrame().Body)
	if err != nil || len(back.SecuredFamilies) != 1 || back.Tunnels == nil || len(back.Tunnels.Slots) != 2 || back.Tunnels.MaxAPDU != 248 ||
		!back.Tunnels.Slots[0].Free || back.Tunnels.Slots[0].Authorised || !back.Tunnels.Slots[1].Authorised || back.Extended == nil || back.Extended.DeviceDescriptor != 0x091A {
		t.Errorf("extended response %+v %v", back, err)
	}
}

// Management services on individual addresses: four-bit services keep
// their six data bits, ten-bit services their whole code, control frames
// their TPCI; busmonitor indications are read with status and timestamp.
// Covers: SIG-IPE-6705
func TestManagementFrames(t *testing.T) {
	dd := knx.IndividualFrame(knx.LDataReq, 0x1105, knx.DeviceDescriptorRead, 0, nil)
	b := dd.Encode()
	if got := hex.EncodeToString(b); got != "1100bc6000001105010300" {
		t.Errorf("DeviceDescriptor_Read = %s", got)
	}
	mr := knx.IndividualFrame(knx.LDataReq, 0x1105, knx.MemoryRead, 4, []byte{0x01, 0x00})
	back, err := knx.ParseLData(mr.Encode())
	if err != nil || back.APCI != knx.MemoryRead || back.Short != 4 || !bytes.Equal(back.Data, []byte{0x01, 0x00}) || back.GroupTarget {
		t.Errorf("Memory_Read %+v %v", back, err)
	}
	if !bytes.Equal(back.Encode(), mr.Encode()) {
		t.Errorf("Memory_Read re-encoded % x, want % x", back.Encode(), mr.Encode())
	}
	pv := knx.IndividualFrame(knx.LDataReq, 0x1105, knx.PropertyValueRead, 0, []byte{0x00, 0x0B, 0x10, 0x01})
	back, err = knx.ParseLData(pv.Encode())
	if err != nil || back.APCI != knx.PropertyValueRead || !bytes.Equal(back.Data, []byte{0x00, 0x0B, 0x10, 0x01}) {
		t.Errorf("PropertyValue_Read %+v %v", back, err)
	}
	conn := knx.ControlFrame(knx.LDataReq, 0x1105, knx.TPCIConnect)
	back, err = knx.ParseLData(conn.Encode())
	if err != nil || !back.Control() || back.TPCI != knx.TPCIConnect || back.Individual() != 0x1105 {
		t.Errorf("T_Connect %+v %v", back, err)
	}
	ack := knx.ControlFrame(knx.LDataReq, 0x1105, knx.TPCIAck|3<<2)
	if back, _ = knx.ParseLData(ack.Encode()); back.TPCI != 0xCE {
		t.Errorf("T_ACK seq 3 TPCI %#x", back.TPCI)
	}
	m, err := knx.ParseBusmon([]byte{knx.LBusmonInd, 7, 0x03, 0x01, 0x05, 0x04, 0x02, 0x12, 0x34, 0xBC, 0x11, 0x01})
	if err != nil || m.Status != 5 || m.Timestamp != 0x1234 || !bytes.Equal(m.Raw, []byte{0xBC, 0x11, 0x01}) {
		t.Errorf("busmon %+v %v", m, err)
	}
	// A layer other than link, raw or busmonitor is refused.
	cr := knx.ConnectRequest{Layer: knx.LayerBusmonitor}.Frame()
	if r, err := knx.ParseConnectRequest(cr.Body); err != nil || r.Layer != knx.LayerBusmonitor {
		t.Errorf("busmonitor CRI %+v %v", r, err)
	}
	cr.Body[len(cr.Body)-2] = 0x07
	if _, err := knx.ParseConnectRequest(cr.Body); err == nil || knx.IsConnTypeError(err) {
		t.Errorf("unknown layer: %v", err)
	}
}
