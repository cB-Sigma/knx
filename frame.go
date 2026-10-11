package knx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// KNXnet/IP frame layer (KNX Standard volume 3 part 8, ISO 22510): a 6-byte
// header (header length 0x06, protocol version 0x10, service type, total
// length) followed by a service-specific body.

// Service type identifiers.
const (
	SvcSearchRequest           uint16 = 0x0201
	SvcSearchResponse          uint16 = 0x0202
	SvcDescriptionRequest      uint16 = 0x0203
	SvcDescriptionResponse     uint16 = 0x0204
	SvcConnectRequest          uint16 = 0x0205
	SvcConnectResponse         uint16 = 0x0206
	SvcConnectionStateRequest  uint16 = 0x0207
	SvcConnectionStateResponse uint16 = 0x0208
	SvcDisconnectRequest       uint16 = 0x0209
	SvcDisconnectResponse      uint16 = 0x020A
	SvcTunnellingRequest       uint16 = 0x0420
	SvcTunnellingAck           uint16 = 0x0421
	SvcRoutingIndication       uint16 = 0x0530
	SvcRoutingLostMessage      uint16 = 0x0531
	SvcRoutingBusy             uint16 = 0x0532
	SvcSearchRequestExtended   uint16 = 0x020B
	SvcSearchResponseExtended  uint16 = 0x020C
	SvcTimerNotify             uint16 = 0x0955
	headerLen                         = 6
	protocolVersion            byte   = 0x10
	hpaiLen                           = 8
	hostProtocolUDP            byte   = 0x01
	hostProtocolTCP            byte   = 0x02
	connTypeTunnel             byte   = 0x04
	tunnelLinkLayer            byte   = 0x02
	dibDeviceInfo              byte   = 0x01
	dibSuppSvcFamilies         byte   = 0x02
	dibDeviceInfoLen                  = 54
	friendlyNameLen                   = 30
	DefaultPort                       = 3671
	DefaultMulticast                  = "224.0.23.12:3671"
)

// Status codes carried in responses and acknowledgements.
const (
	StatusOK               byte = 0x00
	StatusSequenceNumber   byte = 0x04
	StatusConnectionID     byte = 0x21
	StatusConnectionType   byte = 0x22
	StatusConnectionOption byte = 0x23
	StatusNoMoreConns      byte = 0x24
	StatusDataConnection   byte = 0x26
	StatusKNXConnection    byte = 0x27
	StatusTunnellingLayer  byte = 0x29
)

// Service families announced in a supported-service-families DIB.
const (
	FamilyCore       byte = 0x02
	FamilyDeviceMgmt byte = 0x03
	FamilyTunnelling byte = 0x04
	FamilyRouting    byte = 0x05
)

// Medium codes of the device information DIB.
const (
	MediumTP1 byte = 0x02
	MediumIP  byte = 0x20
)

// Frame is one KNXnet/IP frame: service type and body.
type Frame struct {
	Service uint16
	Body    []byte
}

// Encode writes the frame with its header.
func (f Frame) Encode() []byte {
	out := make([]byte, headerLen+len(f.Body))
	out[0], out[1] = headerLen, protocolVersion
	binary.BigEndian.PutUint16(out[2:], f.Service)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)))
	copy(out[headerLen:], f.Body)
	return out
}

// ParseFrame checks the header and splits a datagram into a frame.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < headerLen {
		return Frame{}, errors.New("knxnet/ip: datagram shorter than the header")
	}
	if b[0] != headerLen || b[1] != protocolVersion {
		return Frame{}, fmt.Errorf("knxnet/ip: header length %#x / version %#x not supported", b[0], b[1])
	}
	total := int(binary.BigEndian.Uint16(b[4:]))
	if total < headerLen || total > len(b) {
		return Frame{}, fmt.Errorf("knxnet/ip: total length %d does not match the %d-byte datagram", total, len(b))
	}
	return Frame{Service: binary.BigEndian.Uint16(b[2:]), Body: b[headerLen:total]}, nil
}

// HPAI is a host protocol address information structure: IPv4 over UDP,
// or over TCP (core v2), where it is always the 0.0.0.0:0 "route back"
// form because the stream itself is the endpoint.
type HPAI struct {
	Addr netip.AddrPort
	TCP  bool
}

// TCPHPAI is the HPAI a client sends on a TCP connection.
func TCPHPAI() HPAI {
	return HPAI{Addr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), TCP: true}
}

// HPAIFrom builds an HPAI from a UDP address (unspecified or nil gives
// 0.0.0.0:0, the "reply to the sender" form used behind NAT).
func HPAIFrom(a *net.UDPAddr) HPAI {
	if a == nil {
		return HPAI{Addr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0)}
	}
	ap := a.AddrPort()
	ip := ap.Addr().Unmap()
	if !ip.Is4() {
		ip = netip.IPv4Unspecified()
	}
	return HPAI{Addr: netip.AddrPortFrom(ip, ap.Port())}
}

// Zero reports the 0.0.0.0:0 form.
func (h HPAI) Zero() bool {
	return !h.Addr.IsValid() || (h.Addr.Addr().IsUnspecified() && h.Addr.Port() == 0) || h.Addr.Port() == 0
}

// UDPAddr returns the address, or fallback when the HPAI is the zero form.
func (h HPAI) UDPAddr(fallback *net.UDPAddr) *net.UDPAddr {
	if h.Zero() || h.Addr.Addr().IsUnspecified() {
		return fallback
	}
	return net.UDPAddrFromAddrPort(h.Addr)
}

func (h HPAI) append(b []byte) []byte {
	ip := netip.IPv4Unspecified()
	var port uint16
	if h.Addr.IsValid() {
		ip, port = h.Addr.Addr().Unmap(), h.Addr.Port()
	}
	a4 := ip.As4()
	proto := hostProtocolUDP
	if h.TCP {
		proto = hostProtocolTCP
	}
	b = append(b, hpaiLen, proto)
	b = append(b, a4[:]...)
	return binary.BigEndian.AppendUint16(b, port)
}

func parseHPAI(b []byte) (HPAI, []byte, error) {
	if len(b) < hpaiLen || b[0] != hpaiLen {
		return HPAI{}, nil, errors.New("knxnet/ip: malformed HPAI")
	}
	if b[1] != hostProtocolUDP && b[1] != hostProtocolTCP {
		return HPAI{}, nil, fmt.Errorf("knxnet/ip: host protocol %#x is neither UDP nor TCP", b[1])
	}
	ip := netip.AddrFrom4([4]byte(b[2:6]))
	return HPAI{Addr: netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[6:8])), TCP: b[1] == hostProtocolTCP}, b[hpaiLen:], nil
}

// ---- connection management ---------------------------------------------------

// Tunnelling layers a CONNECT_REQUEST can ask for.
const (
	LayerLink       byte = 0x02 // L_Data frames (the default)
	LayerRaw        byte = 0x04 // L_Raw frames
	LayerBusmonitor byte = 0x80 // L_Busmon.ind of everything on the medium
)

// ConnectRequest asks for a tunnelling connection.
type ConnectRequest struct {
	Control, Data HPAI
	// Layer is the tunnelling layer (zero means LayerLink).
	Layer byte
}

// Frame is the CONNECT_REQUEST frame.
func (r ConnectRequest) Frame() Frame {
	b := r.Control.append(nil)
	b = r.Data.append(b)
	layer := r.Layer
	if layer == 0 {
		layer = tunnelLinkLayer
	}
	b = append(b, 4, connTypeTunnel, layer, 0) // CRI
	return Frame{Service: SvcConnectRequest, Body: b}
}

// ParseConnectRequest decodes a CONNECT_REQUEST body; the CRI must ask for
// a tunnel on the link, raw or busmonitor layer.
func ParseConnectRequest(b []byte) (ConnectRequest, error) {
	var r ConnectRequest
	var err error
	if r.Control, b, err = parseHPAI(b); err != nil {
		return r, err
	}
	if r.Data, b, err = parseHPAI(b); err != nil {
		return r, err
	}
	if len(b) < 2 || int(b[0]) > len(b) || b[0] < 2 {
		return r, errors.New("knxnet/ip: malformed CRI")
	}
	if b[1] != connTypeTunnel {
		return r, fmt.Errorf("knxnet/ip: connection type %#x is not a tunnel: %w", b[1], errConnType)
	}
	if b[0] < 3 {
		return r, fmt.Errorf("knxnet/ip: tunnel CRI without a layer: %w", errConnOption)
	}
	switch b[2] {
	case LayerLink, LayerRaw, LayerBusmonitor:
		r.Layer = b[2]
	default:
		return r, fmt.Errorf("knxnet/ip: tunnel layer %#x not known: %w", b[2], errConnOption)
	}
	return r, nil
}

var (
	errConnType   = errors.New("unsupported connection type")
	errConnOption = errors.New("unsupported connection option")
)

// IsConnTypeError reports a CRI asking for another connection type.
func IsConnTypeError(err error) bool { return errors.Is(err, errConnType) }

// ConnectResponse answers a CONNECT_REQUEST. On a non-zero status only
// Channel and Status are present.
type ConnectResponse struct {
	Channel byte
	Status  byte
	Data    HPAI
	Address IndividualAddress // assigned to the tunnel (from the CRD)
}

// Frame is the CONNECT_RESPONSE frame.
func (r ConnectResponse) Frame() Frame {
	b := []byte{r.Channel, r.Status}
	if r.Status == StatusOK {
		b = r.Data.append(b)
		b = append(b, 4, connTypeTunnel)
		b = binary.BigEndian.AppendUint16(b, uint16(r.Address))
	}
	return Frame{Service: SvcConnectResponse, Body: b}
}

// ParseConnectResponse reads a CONNECT_RESPONSE body.
func ParseConnectResponse(b []byte) (ConnectResponse, error) {
	if len(b) < 2 {
		return ConnectResponse{}, errors.New("knxnet/ip: short connect response")
	}
	r := ConnectResponse{Channel: b[0], Status: b[1]}
	if r.Status != StatusOK {
		return r, nil
	}
	var err error
	if r.Data, b, err = parseHPAI(b[2:]); err != nil {
		return r, err
	}
	if len(b) < 4 || b[0] < 4 || b[1] != connTypeTunnel {
		return r, errors.New("knxnet/ip: malformed CRD")
	}
	r.Address = IndividualAddress(binary.BigEndian.Uint16(b[2:4]))
	return r, nil
}

// ChannelRequest is the body of CONNECTIONSTATE_REQUEST and
// DISCONNECT_REQUEST: channel, reserved byte, control endpoint.
type ChannelRequest struct {
	Channel byte
	Control HPAI
}

// Frame is the request as the given service (CONNECTIONSTATE_REQUEST or
// DISCONNECT_REQUEST).
func (r ChannelRequest) Frame(service uint16) Frame {
	return Frame{Service: service, Body: r.Control.append([]byte{r.Channel, 0})}
}

// ParseChannelRequest reads a CONNECTIONSTATE_REQUEST or
// DISCONNECT_REQUEST body.
func ParseChannelRequest(b []byte) (ChannelRequest, error) {
	if len(b) < 2 {
		return ChannelRequest{}, errors.New("knxnet/ip: short channel request")
	}
	h, _, err := parseHPAI(b[2:])
	return ChannelRequest{Channel: b[0], Control: h}, err
}

// ChannelResponse is the body of CONNECTIONSTATE_RESPONSE and
// DISCONNECT_RESPONSE.
type ChannelResponse struct {
	Channel, Status byte
}

// Frame is the response as the given service (CONNECTIONSTATE_RESPONSE
// or DISCONNECT_RESPONSE).
func (r ChannelResponse) Frame(service uint16) Frame {
	return Frame{Service: service, Body: []byte{r.Channel, r.Status}}
}

// ParseChannelResponse reads a CONNECTIONSTATE_RESPONSE or
// DISCONNECT_RESPONSE body.
func ParseChannelResponse(b []byte) (ChannelResponse, error) {
	if len(b) < 2 {
		return ChannelResponse{}, errors.New("knxnet/ip: short channel response")
	}
	return ChannelResponse{Channel: b[0], Status: b[1]}, nil
}

// ---- tunnelling ------------------------------------------------------------

// TunnelRequest is a TUNNELLING_REQUEST: connection header plus a cEMI
// frame.
type TunnelRequest struct {
	Channel, Seq byte
	CEMI         []byte
}

// Frame is the TUNNELLING_REQUEST frame.
func (r TunnelRequest) Frame() Frame {
	return Frame{Service: SvcTunnellingRequest, Body: append([]byte{4, r.Channel, r.Seq, 0}, r.CEMI...)}
}

// ParseTunnelRequest reads a TUNNELLING_REQUEST body.
func ParseTunnelRequest(b []byte) (TunnelRequest, error) {
	if len(b) < 4 || b[0] != 4 {
		return TunnelRequest{}, errors.New("knxnet/ip: malformed connection header")
	}
	return TunnelRequest{Channel: b[1], Seq: b[2], CEMI: b[4:]}, nil
}

// TunnelAck is a TUNNELLING_ACK.
type TunnelAck struct {
	Channel, Seq, Status byte
}

// Frame is the TUNNELLING_ACK frame.
func (a TunnelAck) Frame() Frame {
	return Frame{Service: SvcTunnellingAck, Body: []byte{4, a.Channel, a.Seq, a.Status}}
}

// ParseTunnelAck reads a TUNNELLING_ACK body.
func ParseTunnelAck(b []byte) (TunnelAck, error) {
	if len(b) < 4 || b[0] != 4 {
		return TunnelAck{}, errors.New("knxnet/ip: malformed tunnelling ack")
	}
	return TunnelAck{Channel: b[1], Seq: b[2], Status: b[3]}, nil
}

// RoutingIndication wraps a cEMI frame for multicast routing.
func RoutingIndication(cemi []byte) Frame {
	return Frame{Service: SvcRoutingIndication, Body: append([]byte(nil), cemi...)}
}

// ---- discovery -------------------------------------------------------------

// DeviceInfo is the device information DIB.
type DeviceInfo struct {
	Medium       byte
	Status       byte
	Address      IndividualAddress
	Project      uint16
	Serial       [6]byte
	Multicast    netip.Addr
	MAC          [6]byte
	FriendlyName string
}

// Family is a supported service family and its version.
type Family struct {
	ID, Version byte
}

// Description is what a gateway says about itself in SEARCH_RESPONSE and
// DESCRIPTION_RESPONSE.
type Description struct {
	Control  HPAI // SEARCH_RESPONSE only
	Device   DeviceInfo
	Families []Family
	// SecuredFamilies lists the service families that need KNX IP Secure
	// (secured service families DIB, core v2).
	SecuredFamilies []Family
	// Tunnels describes the tunnelling slots (tunnelling information DIB,
	// core v2), when the gateway sent it.
	Tunnels *TunnellingInfo
	// Extended is the extended device information DIB, when sent.
	Extended *ExtendedDeviceInfo
}

// TunnellingInfo is the tunnelling information DIB: the largest APDU the
// gateway passes and its tunnelling slots.
type TunnellingInfo struct {
	MaxAPDU uint16
	Slots   []TunnelSlot
}

// TunnelSlot is one tunnelling address and its state.
type TunnelSlot struct {
	Address IndividualAddress
	// Usable, Authorised (open without a secure session or for this user)
	// and Free, as the gateway flags them.
	Usable, Authorised, Free bool
}

// ExtendedDeviceInfo is the extended device information DIB.
type ExtendedDeviceInfo struct {
	MediumStatus     byte
	MaxLocalAPDU     uint16
	DeviceDescriptor uint16 // mask version
}

// Search parameter blocks of SEARCH_REQUEST_EXTENDED (core v2).
type SRP struct {
	Type      byte
	Mandatory bool
	Data      []byte
}

// SRP types.
const (
	SRPProgrammingMode byte = 0x01
	SRPMACAddress      byte = 0x02
	SRPServiceFamily   byte = 0x03
	SRPRequestDIBs     byte = 0x04
)

// DIB types beyond device information and supported families.
const (
	DIBSecuredFamilies byte = 0x06
	DIBTunnellingInfo  byte = 0x07
	DIBExtendedDevice  byte = 0x08
)

// SRPByProgrammingMode asks only gateways in programming mode to answer.
func SRPByProgrammingMode() SRP { return SRP{Type: SRPProgrammingMode, Mandatory: true} }

// SRPByMAC asks only the gateway with this MAC address to answer.
func SRPByMAC(mac [6]byte) SRP { return SRP{Type: SRPMACAddress, Mandatory: true, Data: mac[:]} }

// SRPByService asks only gateways offering the family at least at version.
func SRPByService(family, version byte) SRP {
	return SRP{Type: SRPServiceFamily, Mandatory: true, Data: []byte{family, version}}
}

// SRPWantDIBs asks for these DIB types in the answer.
func SRPWantDIBs(types ...byte) SRP {
	d := append([]byte(nil), types...)
	if len(d)%2 == 1 {
		d = append(d, 0) // padded to an even length
	}
	return SRP{Type: SRPRequestDIBs, Data: d}
}

func (p SRP) append(b []byte) []byte {
	t := p.Type & 0x7F
	if p.Mandatory {
		t |= 0x80
	}
	b = append(b, byte(2+len(p.Data)), t)
	return append(b, p.Data...)
}

// SearchRequestExtended builds a SEARCH_REQUEST_EXTENDED with search
// parameter blocks.
func SearchRequestExtended(discovery HPAI, srps ...SRP) Frame {
	b := discovery.append(nil)
	for _, p := range srps {
		b = p.append(b)
	}
	return Frame{Service: SvcSearchRequestExtended, Body: b}
}

// ParseSearchRequestExtended returns the endpoint and the search parameter
// blocks of a SEARCH_REQUEST_EXTENDED body.
func ParseSearchRequestExtended(b []byte) (HPAI, []SRP, error) {
	h, rest, err := parseHPAI(b)
	if err != nil {
		return h, nil, err
	}
	var out []SRP
	for len(rest) > 0 {
		n := int(rest[0])
		if n < 2 || n > len(rest) {
			return h, out, errors.New("knxnet/ip: malformed search parameter block")
		}
		out = append(out, SRP{Type: rest[1] & 0x7F, Mandatory: rest[1]&0x80 != 0, Data: append([]byte(nil), rest[2:n]...)})
		rest = rest[n:]
	}
	return h, out, nil
}

// Matches reports whether a gateway with this description passes every
// mandatory search parameter block (programming mode is bit 0 of the
// device status).
func (d Description) Matches(srps []SRP) bool {
	for _, p := range srps {
		if !p.Mandatory {
			continue
		}
		switch p.Type {
		case SRPProgrammingMode:
			if d.Device.Status&0x01 == 0 {
				return false
			}
		case SRPMACAddress:
			if len(p.Data) != 6 || [6]byte(p.Data) != d.Device.MAC {
				return false
			}
		case SRPServiceFamily:
			ok := false
			for _, f := range d.Families {
				if len(p.Data) == 2 && f.ID == p.Data[0] && f.Version >= p.Data[1] {
					ok = true
				}
			}
			if !ok {
				return false
			}
		case SRPRequestDIBs:
		default:
			return false // an unknown mandatory block cannot be met
		}
	}
	return true
}

// SearchResponseExtendedFrame builds a SEARCH_RESPONSE_EXTENDED with the
// device information and supported families DIBs and, when set, the
// secured families, tunnelling information and extended device DIBs.
func (d Description) SearchResponseExtendedFrame() Frame {
	b := d.Control.append(nil)
	b = d.Device.append(b)
	b = appendFamilies(b, d.Families)
	if len(d.SecuredFamilies) > 0 {
		b = append(b, byte(2+2*len(d.SecuredFamilies)), DIBSecuredFamilies)
		for _, f := range d.SecuredFamilies {
			b = append(b, f.ID, f.Version)
		}
	}
	if d.Tunnels != nil {
		b = append(b, byte(4+4*len(d.Tunnels.Slots)), DIBTunnellingInfo)
		b = binary.BigEndian.AppendUint16(b, d.Tunnels.MaxAPDU)
		for _, s := range d.Tunnels.Slots {
			var fl byte
			if s.Free {
				fl |= 0x01
			}
			if s.Authorised {
				fl |= 0x02
			}
			if s.Usable {
				fl |= 0x04
			}
			b = binary.BigEndian.AppendUint16(b, uint16(s.Address))
			b = append(b, 0, fl)
		}
	}
	if d.Extended != nil {
		b = append(b, 8, DIBExtendedDevice, d.Extended.MediumStatus, 0)
		b = binary.BigEndian.AppendUint16(b, d.Extended.MaxLocalAPDU)
		b = binary.BigEndian.AppendUint16(b, d.Extended.DeviceDescriptor)
	}
	return Frame{Service: SvcSearchResponseExtended, Body: b}
}

// RoutingBusy is a ROUTING_BUSY: a router asks senders to pause.
type RoutingBusy struct {
	DeviceState byte
	WaitTime    time.Duration // in milliseconds on the wire
	Control     uint16
}

// Frame is the ROUTING_BUSY frame.
func (r RoutingBusy) Frame() Frame {
	b := []byte{6, r.DeviceState}
	b = binary.BigEndian.AppendUint16(b, uint16(r.WaitTime/time.Millisecond))
	return Frame{Service: SvcRoutingBusy, Body: binary.BigEndian.AppendUint16(b, r.Control)}
}

// ParseRoutingBusy reads a ROUTING_BUSY body.
func ParseRoutingBusy(b []byte) (RoutingBusy, error) {
	if len(b) < 6 || b[0] != 6 {
		return RoutingBusy{}, errors.New("knxnet/ip: malformed ROUTING_BUSY")
	}
	return RoutingBusy{DeviceState: b[1], WaitTime: time.Duration(binary.BigEndian.Uint16(b[2:])) * time.Millisecond,
		Control: binary.BigEndian.Uint16(b[4:])}, nil
}

// RoutingLostMessage is a ROUTING_LOST_MESSAGE: a router dropped frames.
type RoutingLostMessage struct {
	DeviceState byte
	Lost        uint16
}

// Frame is the ROUTING_LOST_MESSAGE frame.
func (r RoutingLostMessage) Frame() Frame {
	return Frame{Service: SvcRoutingLostMessage, Body: binary.BigEndian.AppendUint16([]byte{4, r.DeviceState}, r.Lost)}
}

// ParseRoutingLostMessage reads a ROUTING_LOST_MESSAGE body.
func ParseRoutingLostMessage(b []byte) (RoutingLostMessage, error) {
	if len(b) < 4 || b[0] != 4 {
		return RoutingLostMessage{}, errors.New("knxnet/ip: malformed ROUTING_LOST_MESSAGE")
	}
	return RoutingLostMessage{DeviceState: b[1], Lost: binary.BigEndian.Uint16(b[2:])}, nil
}

// Supports reports whether the gateway announces a service family.
func (d Description) Supports(family byte) bool {
	for _, f := range d.Families {
		if f.ID == family {
			return true
		}
	}
	return false
}

func (d DeviceInfo) append(b []byte) []byte {
	b = append(b, dibDeviceInfoLen, dibDeviceInfo, d.Medium, d.Status)
	b = binary.BigEndian.AppendUint16(b, uint16(d.Address))
	b = binary.BigEndian.AppendUint16(b, d.Project)
	b = append(b, d.Serial[:]...)
	m := netip.IPv4Unspecified()
	if d.Multicast.Is4() {
		m = d.Multicast
	}
	a4 := m.As4()
	b = append(b, a4[:]...)
	b = append(b, d.MAC[:]...)
	// ISO 8859-1, zero padded, keeping a terminating zero.
	name := make([]byte, friendlyNameLen)
	i := 0
	for _, r := range d.FriendlyName {
		if i == friendlyNameLen-1 {
			break
		}
		if r > 0xFF {
			r = '?'
		}
		name[i] = byte(r)
		i++
	}
	return append(b, name...)
}

func appendFamilies(b []byte, fs []Family) []byte {
	b = append(b, byte(2+2*len(fs)), dibSuppSvcFamilies)
	for _, f := range fs {
		b = append(b, f.ID, f.Version)
	}
	return b
}

// SearchResponseFrame builds a SEARCH_RESPONSE.
func (d Description) SearchResponseFrame() Frame {
	b := d.Control.append(nil)
	b = d.Device.append(b)
	return Frame{Service: SvcSearchResponse, Body: appendFamilies(b, d.Families)}
}

// DescriptionResponseFrame builds a DESCRIPTION_RESPONSE.
func (d Description) DescriptionResponseFrame() Frame {
	b := d.Device.append(nil)
	return Frame{Service: SvcDescriptionResponse, Body: appendFamilies(b, d.Families)}
}

// ParseSearchResponse decodes a SEARCH_RESPONSE body.
func ParseSearchResponse(b []byte) (Description, error) {
	h, rest, err := parseHPAI(b)
	if err != nil {
		return Description{}, err
	}
	d, err := parseDIBs(rest)
	d.Control = h
	return d, err
}

// ParseDescriptionResponse decodes a DESCRIPTION_RESPONSE body.
func ParseDescriptionResponse(b []byte) (Description, error) { return parseDIBs(b) }

func parseDIBs(b []byte) (Description, error) {
	var d Description
	seenDev := false
	for len(b) >= 2 {
		n := int(b[0])
		if n < 2 || n > len(b) {
			return d, errors.New("knxnet/ip: malformed DIB length")
		}
		dib := b[:n]
		switch b[1] {
		case dibDeviceInfo:
			if n != dibDeviceInfoLen {
				return d, fmt.Errorf("knxnet/ip: device information DIB of %d bytes", n)
			}
			di := DeviceInfo{Medium: dib[2], Status: dib[3],
				Address: IndividualAddress(binary.BigEndian.Uint16(dib[4:])),
				Project: binary.BigEndian.Uint16(dib[6:])}
			copy(di.Serial[:], dib[8:14])
			di.Multicast = netip.AddrFrom4([4]byte(dib[14:18]))
			copy(di.MAC[:], dib[18:24])
			name := dib[24:54]
			for i, c := range name {
				if c == 0 {
					name = name[:i]
					break
				}
			}
			di.FriendlyName = latin1(name)
			d.Device, seenDev = di, true
		case dibSuppSvcFamilies:
			for i := 2; i+1 < n; i += 2 {
				d.Families = append(d.Families, Family{ID: dib[i], Version: dib[i+1]})
			}
		case DIBSecuredFamilies:
			for i := 2; i+1 < n; i += 2 {
				d.SecuredFamilies = append(d.SecuredFamilies, Family{ID: dib[i], Version: dib[i+1]})
			}
		case DIBTunnellingInfo:
			if n >= 4 {
				ti := &TunnellingInfo{MaxAPDU: binary.BigEndian.Uint16(dib[2:])}
				for i := 4; i+3 < n; i += 4 {
					fl := dib[i+3]
					ti.Slots = append(ti.Slots, TunnelSlot{Address: IndividualAddress(binary.BigEndian.Uint16(dib[i:])),
						Free: fl&0x01 != 0, Authorised: fl&0x02 != 0, Usable: fl&0x04 != 0})
				}
				d.Tunnels = ti
			}
		case DIBExtendedDevice:
			if n >= 8 {
				d.Extended = &ExtendedDeviceInfo{MediumStatus: dib[2], MaxLocalAPDU: binary.BigEndian.Uint16(dib[4:]),
					DeviceDescriptor: binary.BigEndian.Uint16(dib[6:])}
			}
		}
		b = b[n:]
	}
	if !seenDev {
		return d, errors.New("knxnet/ip: no device information DIB")
	}
	return d, nil
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// SearchRequest builds a SEARCH_REQUEST naming the endpoint that wants the
// responses.
func SearchRequest(discovery HPAI) Frame {
	return Frame{Service: SvcSearchRequest, Body: discovery.append(nil)}
}

// DescriptionRequest builds a DESCRIPTION_REQUEST.
func DescriptionRequest(control HPAI) Frame {
	return Frame{Service: SvcDescriptionRequest, Body: control.append(nil)}
}

// ParseEndpointRequest decodes the single HPAI body of SEARCH_REQUEST and
// DESCRIPTION_REQUEST.
func ParseEndpointRequest(b []byte) (HPAI, error) {
	h, _, err := parseHPAI(b)
	return h, err
}
