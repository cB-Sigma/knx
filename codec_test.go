package knx_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/cB-Sigma/knx"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hpai(s string) knx.HPAI {
	return knx.HPAI{Addr: netip.MustParseAddrPort(s)}
}

// Covers: SIG-IPE-440
func TestKNXFrameCodec(t *testing.T) {
	ctl := hpai("192.168.1.10:3671")
	for _, tc := range []struct {
		name string
		f    knx.Frame
		want string
	}{
		{"connect request", knx.ConnectRequest{Control: ctl, Data: ctl}.Frame(),
			"06100205001a" + "0801c0a8010a0e57" + "0801c0a8010a0e57" + "04040200"},
		{"connect response", knx.ConnectResponse{Channel: 0x15, Data: hpai("192.168.1.20:3671"), Address: 0x11FA}.Frame(),
			"061002060014" + "1500" + "0801c0a801140e57" + "040411fa"},
		{"connect refused", knx.ConnectResponse{Channel: 0, Status: knx.StatusNoMoreConns}.Frame(), "0610020600080024"},
		{"connectionstate request", knx.ChannelRequest{Channel: 0x15, Control: ctl}.Frame(knx.SvcConnectionStateRequest),
			"061002070010" + "1500" + "0801c0a8010a0e57"},
		{"connectionstate response", knx.ChannelResponse{Channel: 0x15}.Frame(knx.SvcConnectionStateResponse), "0610020800081500"},
		{"disconnect request", knx.ChannelRequest{Channel: 7, Control: ctl}.Frame(knx.SvcDisconnectRequest),
			"061002090010" + "0700" + "0801c0a8010a0e57"},
		{"disconnect response", knx.ChannelResponse{Channel: 7}.Frame(knx.SvcDisconnectResponse), "0610020a00080700"},
		{"tunnelling ack", knx.TunnelAck{Channel: 0x15, Seq: 7}.Frame(), "06100421000a04150700"},
		{"tunnelling request", knx.TunnelRequest{Channel: 0x15, Seq: 3, CEMI: unhex(t, "1100bce000000a03010081")}.Frame(),
			"061004200015" + "04150300" + "1100bce000000a03010081"},
		{"routing indication", knx.RoutingIndication(unhex(t, "2900bce011010a03010081")), "061005300011" + "2900bce011010a03010081"},
		{"search request", knx.SearchRequest(ctl), "06100201000e0801c0a8010a0e57"},
		{"description request", knx.DescriptionRequest(ctl), "06100203000e0801c0a8010a0e57"},
	} {
		got := tc.f.Encode()
		if want := unhex(t, tc.want); !bytes.Equal(got, want) {
			t.Errorf("%s = % x, want % x", tc.name, got, want)
		}
		back, err := knx.ParseFrame(got)
		if err != nil || back.Service != tc.f.Service || !bytes.Equal(back.Body, tc.f.Body) {
			t.Errorf("%s: parse = %+v, %v", tc.name, back, err)
		}
	}

	// Parsers invert the builders.
	cr, err := knx.ParseConnectRequest(knx.ConnectRequest{Control: ctl, Data: hpai("10.0.0.1:50000")}.Frame().Body)
	if err != nil || cr.Control != ctl || cr.Data.Addr.String() != "10.0.0.1:50000" {
		t.Errorf("connect request = %+v, %v", cr, err)
	}
	resp, err := knx.ParseConnectResponse(unhex(t, "1500"+"0801c0a801140e57"+"040411fa"))
	if err != nil || resp.Channel != 0x15 || resp.Address.String() != "1.1.250" || resp.Data.Addr.String() != "192.168.1.20:3671" {
		t.Errorf("connect response = %+v, %v", resp, err)
	}
	ack, err := knx.ParseTunnelAck(unhex(t, "04150729"))
	if err != nil || ack != (knx.TunnelAck{Channel: 0x15, Seq: 7, Status: 0x29}) {
		t.Errorf("ack = %+v, %v", ack, err)
	}
	// A CRI for device management (0x03) is refused as a connection type.
	bad := unhex(t, "0801c0a8010a0e57"+"0801c0a8010a0e57"+"0203")
	if _, err := knx.ParseConnectRequest(bad); !knx.IsConnTypeError(err) {
		t.Errorf("device management CRI: %v", err)
	}
	// The zero HPAI means "answer the sender".
	from := &net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 4000}
	if got := knx.HPAIFrom(nil).UDPAddr(from); got != from {
		t.Errorf("zero HPAI resolves to %v", got)
	}

	// Discovery DIBs round trip; the device information DIB is 54 bytes.
	d := knx.Description{Control: ctl, Device: knx.DeviceInfo{Medium: knx.MediumTP1, Address: 0x11FF, Project: 0x0102,
		Serial: [6]byte{0, 0xC5, 1, 2, 3, 4}, Multicast: netip.MustParseAddr("224.0.23.12"), MAC: [6]byte{2, 0, 0, 0, 0, 1},
		FriendlyName: "Gateway Büro"},
		Families: []knx.Family{{knx.FamilyCore, 1}, {knx.FamilyTunnelling, 1}, {knx.FamilyRouting, 1}}}
	sr := d.SearchResponseFrame()
	if len(sr.Body) != 8+54+8 || sr.Body[8] != 54 || sr.Body[9] != 0x01 || sr.Body[62] != 8 || sr.Body[63] != 0x02 {
		t.Errorf("search response body = % x", sr.Body)
	}
	got, err := knx.ParseSearchResponse(sr.Body)
	if err != nil || got.Device.FriendlyName != "Gateway Büro" || got.Device.Address.String() != "1.1.255" ||
		got.Device.Multicast.String() != "224.0.23.12" || !got.Supports(knx.FamilyRouting) || got.Supports(knx.FamilyDeviceMgmt) || got.Control != ctl {
		t.Errorf("search response = %+v, %v", got, err)
	}
	dr, err := knx.ParseDescriptionResponse(d.DescriptionResponseFrame().Body)
	if err != nil || dr.Device.Serial != d.Device.Serial || len(dr.Families) != 3 {
		t.Errorf("description response = %+v, %v", dr, err)
	}

	// Malformed headers are refused.
	for _, b := range []string{"0610", "0710020600080024", "0620020600080024", "0610020600ff0024"} {
		if _, err := knx.ParseFrame(unhex(t, b)); err == nil {
			t.Errorf("header %s accepted", b)
		}
	}
}

// Covers: SIG-IPE-441
func TestKNXCEMIAndAddresses(t *testing.T) {
	for _, tc := range []struct {
		s    string
		ga   knx.GroupAddress
		back string
	}{
		{"1/2/3", 0x0A03, "1/2/3"}, {"31/7/255", 0xFFFF, "31/7/255"}, {"0/0/1", 1, "0/0/1"},
		{"1/515", 0x0A03, "1/2/3"}, {"2563", 0x0A03, "1/2/3"},
	} {
		ga, err := knx.ParseGroupAddress(tc.s)
		if err != nil || ga != tc.ga || ga.String() != tc.back {
			t.Errorf("%s = %#04x (%s), %v", tc.s, uint16(ga), ga, err)
		}
	}
	if g, _ := knx.ParseGroupAddress("1/2/3"); g.TwoLevel() != "1/515" {
		t.Errorf("two-level form = %s", g.TwoLevel())
	}
	for _, bad := range []string{"32/0/0", "1/8/0", "1/2/256", "1/2048", "a/b/c", "1/2/3/4", ""} {
		if _, err := knx.ParseGroupAddress(bad); err == nil {
			t.Errorf("group address %q accepted", bad)
		}
	}
	ia, err := knx.ParseIndividualAddress("1.1.250")
	if err != nil || ia != 0x11FA || ia.String() != "1.1.250" {
		t.Errorf("individual address = %#04x, %v", uint16(ia), err)
	}
	if _, err := knx.ParseIndividualAddress("16.0.1"); err == nil {
		t.Error("area 16 accepted")
	}

	ga, _ := knx.ParseGroupAddress("1/2/3")
	for _, tc := range []struct {
		name  string
		f     knx.LData
		want  string
		short bool
	}{
		// L_Data.req, standard frame, low priority, group destination,
		// hop count 6: switch on (short data in the APCI octet).
		{"write short", knx.GroupFrame(knx.LDataReq, ga, knx.GroupValueWrite, []byte{1}, true), "1100bce000000a03010081", true},
		// 21 °C as DPT 9 (long data after the APCI octet).
		{"write long", knx.GroupFrame(knx.LDataReq, ga, knx.GroupValueWrite, []byte{0x0C, 0x1A}, false), "1100bce000000a030300800c1a", false},
		{"read", knx.GroupFrame(knx.LDataReq, ga, knx.GroupValueRead, nil, true), "1100bce000000a03010000", true},
		{"response", knx.GroupFrame(knx.LDataInd, ga, knx.GroupValueResponse, []byte{0x40}, false), "2900bce000000a0302004040", false},
	} {
		got := tc.f.Encode()
		if want := unhex(t, tc.want); !bytes.Equal(got, want) {
			t.Errorf("%s = % x, want % x", tc.name, got, want)
		}
		back, err := knx.ParseLData(got)
		if err != nil || back.Code != tc.f.Code || back.APCI != tc.f.APCI || back.Group() != ga || !back.GroupTarget ||
			back.IsShort != tc.short || !bytes.Equal(back.Value(), tc.f.Value()) {
			t.Errorf("%s: parsed %+v, %v", tc.name, back, err)
		}
	}
	// An indication from 1.1.10 with additional information, and a
	// negative confirmation.
	ind, err := knx.ParseLData(unhex(t, "2902ff00bce0110a0a03010080"))
	if err != nil || ind.Source.String() != "1.1.10" || ind.APCI != knx.GroupValueWrite || ind.Value()[0] != 0 || len(ind.AddInfo) != 2 {
		t.Errorf("indication = %+v, %v", ind, err)
	}
	con, _ := knx.ParseLData(unhex(t, "2e00bde011fa0a03010081"))
	if con.Code != knx.LDataCon || con.Confirmed() {
		t.Errorf("negative confirmation read as %+v", con)
	}
	con, _ = knx.ParseLData(unhex(t, "2e00bce011fa0a03010081"))
	if !con.Confirmed() {
		t.Error("positive confirmation not recognised")
	}
	if _, err := knx.ParseLData(unhex(t, "fc000001")); !errors.Is(err, knx.ErrNotLData) {
		t.Errorf("a property read is not L_Data: %v", err)
	}
	if _, err := knx.ParseLData(unhex(t, "2900bce0110a0a0305008040")); err == nil {
		t.Error("a length beyond the frame was accepted")
	}
}

// Covers: SIG-IPE-442
func TestKNXDatapointTypes(t *testing.T) {
	for _, tc := range []struct {
		dpt  string
		v    any
		raw  string
		back any
		unit string
	}{
		{"1.001", true, "01", true, ""},
		{"1.001", "off", "00", false, ""},
		{"5.001", 100.0, "ff", 100.0, "%"},
		{"5.001", 50.0, "80", 50.2, "%"},
		{"5.001", 0.0, "00", 0.0, "%"},
		{"5.003", 360.0, "ff", 360.0, "deg"},
		{"5.010", 42.0, "2a", 42.0, ""},
		{"7.001", 65535.0, "ffff", 65535.0, ""},
		{"7.013", 500.0, "01f4", 500.0, "lx"},
		{"9.001", 21.0, "0c1a", 21.0, "Cel"},
		{"9.001", 0.0, "0000", 0.0, "Cel"},
		{"9.001", -30.0, "8a24", -30.0, "Cel"},
		{"9.001", 0.01, "0001", 0.01, "Cel"},
		{"9.001", -0.01, "87ff", -0.01, "Cel"},
		{"9.001", 20.48, "0c00", 20.48, "Cel"},
		{"9.001", -671088.64, "f800", -671088.64, "Cel"},
		{"9.004", 1000.0, "361b", 1000.32, "lx"},
		{"9.007", 45.5, "1472", 45.52, "%"},
		{"13.001", -1.0, "ffffffff", -1.0, ""},
		{"13.010", 2147483647.0, "7fffffff", 2147483647.0, "Wh"},
		{"14.056", 1234.5, "449a5000", 1234.5, "W"},
		{"14.019", -0.25, "be800000", -0.25, "A"},
		{"16.000", "KNX is OK", "4b4e58206973204f4b0000000000", "KNX is OK", ""},
		{"16.001", "Büro", "42fc726f000000000000000000", nil, ""},
		{"20.102", "economy", "03", 3.0, ""},
		{"20.102", 1.0, "01", 1.0, ""},
	} {
		d, err := knx.ParseDPT(tc.dpt)
		if err != nil {
			t.Fatalf("%s: %v", tc.dpt, err)
		}
		if d.Unit() != tc.unit {
			t.Errorf("%s unit = %q, want %q", tc.dpt, d.Unit(), tc.unit)
		}
		raw, err := d.Encode(tc.v)
		if tc.dpt == "16.001" {
			// 14 bytes, Latin-1.
			if err != nil || len(raw) != 14 || raw[1] != 0xFC {
				t.Errorf("16.001 Büro = % x, %v", raw, err)
			}
			if v, _ := d.Decode(raw); v != "Büro" {
				t.Errorf("16.001 decode = %v", v)
			}
			continue
		}
		if err != nil || hex.EncodeToString(raw) != tc.raw {
			t.Errorf("%s %v = %x, %v; want %s", tc.dpt, tc.v, raw, err, tc.raw)
			continue
		}
		back, err := d.Decode(raw)
		if f, ok := tc.back.(float64); ok {
			g, _ := back.(float64)
			if err != nil || math.Abs(g-f) > 1e-9 {
				t.Errorf("%s decode %s = %v, %v; want %v", tc.dpt, tc.raw, back, err, tc.back)
			}
		} else if err != nil || back != tc.back {
			t.Errorf("%s decode %s = %v, %v; want %v", tc.dpt, tc.raw, back, err, tc.back)
		}
	}
	// DPT 9 round trips across its range within its resolution.
	for _, v := range []float64{-273, -20.48, -1, 0.5, 19.99, 100, 1500.5, 100000, 670433.28} {
		w, err := knx.EncodeFloat16(v)
		if err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		got, _ := knx.DecodeFloat16(w)
		e := int(w>>11) & 0xF
		if res := 0.01 * float64(int(1)<<e); math.Abs(got-v) > res/2+1e-9 {
			t.Errorf("DPT 9 %v -> %#04x -> %v", v, w, got)
		}
	}
	if _, err := knx.DecodeFloat16(0x7FFF); !errors.Is(err, knx.ErrInvalidFloat16) {
		t.Errorf("0x7FFF decoded without the invalid-data error: %v", err)
	}
	// Out of range and wrong types are refused.
	for _, tc := range []struct {
		dpt string
		v   any
	}{
		{"1.001", 2.0}, {"1.001", "maybe"}, {"5.001", 101.0}, {"5.010", 256.0}, {"5.010", -1.0}, {"7.001", 65536.0},
		{"7.001", 1.5}, {"9.001", 670760.96}, {"9.001", -700000.0}, {"13.001", 3e9}, {"16.000", "fifteen chars!!"},
		{"16.000", "é"}, {"20.102", "party"}, {"9.001", map[string]any{}},
	} {
		d, _ := knx.ParseDPT(tc.dpt)
		if raw, err := d.Encode(tc.v); err == nil {
			t.Errorf("%s accepted %v as % x", tc.dpt, tc.v, raw)
		}
	}
	for _, s := range []string{"DPT9.001", "dpst-9-1", "9.1"} {
		if d, err := knx.ParseDPT(s); err != nil || d.String() != "9.001" {
			t.Errorf("%s = %v, %v", s, d, err)
		}
	}
	for _, s := range []string{"232.600", "x", "5.002"} {
		if _, err := knx.ParseDPT(s); err == nil {
			t.Errorf("unsupported DPT %s accepted", s)
		}
	}
}
