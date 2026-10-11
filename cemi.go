package knx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// cEMI link-layer data frames (KNX Standard volume 3 part 6 clause 3,
// common EMI): message code, additional information, two control fields,
// source and destination addresses and the TPDU.

// Message codes.
const (
	LDataReq byte = 0x11
	LDataCon byte = 0x2E
	LDataInd byte = 0x29
	// LBusmonInd carries a raw frame seen on the medium (busmonitor tunnels).
	LBusmonInd byte = 0x2B
	// LRawReq, LRawCon and LRawInd carry raw frames (raw tunnels).
	LRawReq byte = 0x10
	LRawCon byte = 0x2F
	LRawInd byte = 0x2D
)

// Application-layer services on group addresses (10-bit APCI values).
const (
	GroupValueRead     uint16 = 0x000
	GroupValueResponse uint16 = 0x040
	GroupValueWrite    uint16 = 0x080
)

// Application-layer services on individual addresses and broadcasts
// (KNX Standard volume 3 part 3 clause 7, application layer). The four-bit
// services carry six bits of data in the APCI octet (Short); the ones from
// 0x3C0 up use all ten bits and carry their data after it.
const (
	IndividualAddressWrite    uint16 = 0x0C0
	IndividualAddressRead     uint16 = 0x100
	IndividualAddressResponse uint16 = 0x140
	ADCRead                   uint16 = 0x180
	ADCResponse               uint16 = 0x1C0
	MemoryRead                uint16 = 0x200
	MemoryResponse            uint16 = 0x240
	MemoryWrite               uint16 = 0x280
	UserMessage               uint16 = 0x2C0
	DeviceDescriptorRead      uint16 = 0x300
	DeviceDescriptorResponse  uint16 = 0x340
	Restart                   uint16 = 0x380
	Escape                    uint16 = 0x3C0

	AuthorizeRequest              uint16 = 0x3D1
	AuthorizeResponse             uint16 = 0x3D2
	KeyWrite                      uint16 = 0x3D3
	KeyResponse                   uint16 = 0x3D4
	PropertyValueRead             uint16 = 0x3D5
	PropertyValueResponse         uint16 = 0x3D6
	PropertyValueWrite            uint16 = 0x3D7
	PropertyDescriptionRead       uint16 = 0x3D8
	PropertyDescriptionResponse   uint16 = 0x3D9
	IndividualAddressSerialRead   uint16 = 0x3DC
	IndividualAddressSerialResp   uint16 = 0x3DD
	IndividualAddressSerialWrite  uint16 = 0x3DE
	DomainAddressWrite            uint16 = 0x3E0
	DomainAddressRead             uint16 = 0x3E1
	DomainAddressResponse         uint16 = 0x3E2
	FunctionPropertyCommand       uint16 = 0x2C7
	FunctionPropertyStateRead     uint16 = 0x2C8
	FunctionPropertyStateResponse uint16 = 0x2C9
	// SecureService is the APCI of KNX Data Secure (S-A_Data and the sync
	// services); see DataSecure.
	SecureService uint16 = 0x3F1
)

// Transport-layer control (TPCI) octet values for point-to-point use.
const (
	TPCIDataIndividual byte = 0x00 // T_Data_Individual (connectionless)
	TPCIConnect        byte = 0x80 // T_Connect
	TPCIDisconnect     byte = 0x81 // T_Disconnect
	TPCINumbered       byte = 0x40 // T_Data_Connected: OR the sequence number << 2
	TPCIAck            byte = 0xC2 // T_ACK: OR the sequence number << 2
	TPCINak            byte = 0xC3 // T_NAK: OR the sequence number << 2
)

// apciLong reports a ten-bit service: escape-class codes and the user
// message codes other than the plain 0x2C0 class carry all ten bits.
func apciLong(top uint16) bool { return top == Escape || top == UserMessage }

// Control field 1 bits.
const (
	ctrl1Standard    byte = 0x80 // standard (not extended) frame
	ctrl1NoRepeat    byte = 0x20 // do not repeat on error
	ctrl1Broadcast   byte = 0x10 // normal (not system) broadcast
	ctrl1PrioLow     byte = 0x0C
	ctrl1ConfirmErr  byte = 0x01 // L_Data.con: transmission failed
	ctrl2GroupDest   byte = 0x80
	ctrl2DefaultHops byte = 0x60 // hop count 6
)

// IndividualAddress is a device address area.line.device (4/4/8 bits).
type IndividualAddress uint16

// String formats the address as area.line.device, such as "1.1.250".
func (a IndividualAddress) String() string {
	return fmt.Sprintf("%d.%d.%d", a>>12, (a>>8)&0x0F, a&0xFF)
}

// ParseIndividualAddress reads "1.1.250".
func ParseIndividualAddress(s string) (IndividualAddress, error) {
	p := strings.Split(s, ".")
	if len(p) != 3 {
		return 0, fmt.Errorf("individual address %q is not area.line.device", s)
	}
	a, err1 := strconv.ParseUint(p[0], 10, 8)
	l, err2 := strconv.ParseUint(p[1], 10, 8)
	d, err3 := strconv.ParseUint(p[2], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil || a > 15 || l > 15 {
		return 0, fmt.Errorf("individual address %q is out of range (0-15.0-15.0-255)", s)
	}
	return IndividualAddress(a<<12 | l<<8 | d), nil
}

// GroupAddress is a 16-bit group address.
type GroupAddress uint16

// String prints the three-level form main/middle/sub (5/3/8 bits).
func (g GroupAddress) String() string {
	return fmt.Sprintf("%d/%d/%d", g>>11, (g>>8)&0x07, g&0xFF)
}

// TwoLevel prints the two-level form main/sub (5/11 bits).
func (g GroupAddress) TwoLevel() string {
	return fmt.Sprintf("%d/%d", g>>11, g&0x07FF)
}

// ParseGroupAddress reads "1/2/3" (three-level), "1/515" (two-level) or a
// plain number (free-style).
func ParseGroupAddress(s string) (GroupAddress, error) {
	p := strings.Split(strings.TrimSpace(s), "/")
	n := make([]uint64, len(p))
	for i, x := range p {
		v, err := strconv.ParseUint(x, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("group address %q: %q is not a number", s, x)
		}
		n[i] = v
	}
	switch len(p) {
	case 3:
		if n[0] > 31 || n[1] > 7 || n[2] > 255 {
			return 0, fmt.Errorf("group address %q is out of range (0-31/0-7/0-255)", s)
		}
		return GroupAddress(n[0]<<11 | n[1]<<8 | n[2]), nil
	case 2:
		if n[0] > 31 || n[1] > 2047 {
			return 0, fmt.Errorf("group address %q is out of range (0-31/0-2047)", s)
		}
		return GroupAddress(n[0]<<11 | n[1]), nil
	case 1:
		return GroupAddress(n[0]), nil
	}
	return 0, fmt.Errorf("group address %q is not main/middle/sub or main/sub", s)
}

// LData is a cEMI L_Data frame carrying a group-value service. Other
// transport services (connection-oriented, individual destinations) are
// decoded far enough to be recognised and skipped.
type LData struct {
	Code        byte
	Ctrl1       byte
	Ctrl2       byte
	Source      IndividualAddress
	Dest        uint16 // group or individual, per Ctrl2
	APCI        uint16 // 10-bit application service
	Data        []byte // long data (after the APCI octet)
	Short       byte   // 6-bit data inside the APCI octet
	IsShort     bool   // the value travels in Short
	TPCI        byte
	AddInfo     []byte
	GroupTarget bool
}

// GroupFrame builds an L_Data frame for a group service. With short true the
// value is the low 6 bits of data[0] (DPT 1, 2 and 3); otherwise data follows
// the APCI.
func GroupFrame(code byte, dest GroupAddress, apci uint16, data []byte, short bool) LData {
	f := LData{Code: code, Ctrl1: ctrl1Standard | ctrl1NoRepeat | ctrl1Broadcast | ctrl1PrioLow,
		Ctrl2: ctrl2GroupDest | ctrl2DefaultHops, Dest: uint16(dest), APCI: apci, GroupTarget: true}
	if short && len(data) > 0 {
		f.IsShort, f.Short = true, data[0]&0x3F
	} else if !short {
		f.Data = append([]byte(nil), data...)
	} else {
		f.IsShort = true
	}
	return f
}

// Group returns the destination as a group address.
func (f LData) Group() GroupAddress { return GroupAddress(f.Dest) }

// Confirmed reports an L_Data.con without the error flag.
func (f LData) Confirmed() bool { return f.Code == LDataCon && f.Ctrl1&ctrl1ConfirmErr == 0 }

// Value returns the application data: the 6-bit value as one byte for short
// frames, the long data otherwise.
func (f LData) Value() []byte {
	if f.IsShort {
		return []byte{f.Short}
	}
	return f.Data
}

// IndividualFrame builds a connectionless point-to-point L_Data frame (an
// individual destination, T_Data_Individual) for a management service such
// as DeviceDescriptorRead or PropertyValueRead. For the four-bit services
// short carries the six data bits in the APCI octet (for example the
// descriptor type of DeviceDescriptorRead); data follows the APCI.
func IndividualFrame(code byte, dest IndividualAddress, apci uint16, short byte, data []byte) LData {
	f := LData{Code: code, Ctrl1: ctrl1Standard | ctrl1NoRepeat | ctrl1Broadcast | ctrl1PrioLow,
		Ctrl2: ctrl2DefaultHops, Dest: uint16(dest), APCI: apci, TPCI: TPCIDataIndividual}
	if !apciLong(apci&0x3C0) && len(data) == 0 {
		f.IsShort, f.Short = true, short&0x3F
	} else {
		if !apciLong(apci & 0x3C0) {
			f.APCI = apci&0x3C0 | uint16(short&0x3F)
		}
		f.Data = append([]byte(nil), data...)
	}
	return f
}

// ControlFrame builds a transport-layer control frame to an individual
// address: T_Connect, T_Disconnect, or T_ACK / T_NAK with the sequence
// number OR-ed in (TPCIAck | seq<<2).
func ControlFrame(code byte, dest IndividualAddress, tpci byte) LData {
	return LData{Code: code, Ctrl1: ctrl1Standard | ctrl1NoRepeat | ctrl1Broadcast | ctrl1PrioLow,
		Ctrl2: ctrl2DefaultHops, Dest: uint16(dest), TPCI: tpci}
}

// Control reports a transport-layer control frame (no application data).
func (f LData) Control() bool { return f.TPCI&0x80 != 0 }

// Individual returns the destination as an individual address.
func (f LData) Individual() IndividualAddress { return IndividualAddress(f.Dest) }

// Extended reports an extended frame (more than 15 octets of TPDU after the
// TPCI octet, or flagged so in control field 1).
func (f LData) Extended() bool { return f.Ctrl1&ctrl1Standard == 0 }

// apdu is the TPCI octet, the APCI and the data, as the frame carries them.
func (f LData) apdu() []byte {
	if f.Control() {
		return []byte{f.TPCI}
	}
	apdu := []byte{f.TPCI&0xFC | byte(f.APCI>>8)&0x03, byte(f.APCI)}
	switch {
	case f.IsShort:
		apdu[1] |= f.Short & 0x3F
	case apciLong(f.APCI & 0x3C0):
		apdu = append(apdu, f.Data...)
	default:
		apdu[1] |= f.Short & 0x3F
		apdu = append(apdu, f.Data...)
	}
	return apdu
}

// Encode writes the cEMI frame. A frame whose TPDU does not fit a standard
// frame (more than 15 octets after the TPCI octet) is sent as an extended
// frame.
func (f LData) Encode() []byte {
	b := []byte{f.Code, byte(len(f.AddInfo))}
	b = append(b, f.AddInfo...)
	ctrl2 := f.Ctrl2
	if f.GroupTarget {
		ctrl2 |= ctrl2GroupDest
	}
	apdu := f.apdu()
	ctrl1 := f.Ctrl1
	if len(apdu)-1 > 15 {
		ctrl1 &^= ctrl1Standard
	}
	b = append(b, ctrl1, ctrl2)
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Dest)
	b = append(b, byte(len(apdu)-1)) // octets after the TPCI octet
	return append(b, apdu...)
}

// ErrNotLData is returned for cEMI messages other than L_Data.
var ErrNotLData = errors.New("cemi: not an L_Data frame")

// ParseLData decodes a cEMI L_Data frame.
func ParseLData(b []byte) (LData, error) {
	if len(b) < 2 {
		return LData{}, errors.New("cemi: frame too short")
	}
	var f LData
	f.Code = b[0]
	switch f.Code {
	case LDataReq, LDataCon, LDataInd:
	default:
		return f, fmt.Errorf("%w (message code %#02x)", ErrNotLData, f.Code)
	}
	ai := int(b[1])
	if len(b) < 2+ai+7 {
		return f, errors.New("cemi: L_Data frame too short")
	}
	f.AddInfo = append([]byte(nil), b[2:2+ai]...)
	b = b[2+ai:]
	f.Ctrl1, f.Ctrl2 = b[0], b[1]
	f.Source = IndividualAddress(binary.BigEndian.Uint16(b[2:]))
	f.Dest = binary.BigEndian.Uint16(b[4:])
	f.GroupTarget = f.Ctrl2&ctrl2GroupDest != 0
	n := int(b[6])
	apdu := b[7:]
	if len(apdu) < n+1 {
		return f, fmt.Errorf("cemi: length says %d octets after TPCI, only %d present", n, len(apdu)-1)
	}
	apdu = apdu[:n+1]
	if n == 0 {
		// A bare TPCI (transport control, no application data).
		f.TPCI = apdu[0]
		return f, nil
	}
	f.TPCI = apdu[0] & 0xFC
	top := uint16(apdu[0]&0x03)<<8 | uint16(apdu[1]&0xC0)
	if apciLong(top) {
		// Ten-bit service: the whole APCI, data after it.
		f.APCI = uint16(apdu[0]&0x03)<<8 | uint16(apdu[1])
		f.Data = append([]byte(nil), apdu[2:]...)
		return f, nil
	}
	f.APCI = top
	if n == 1 {
		f.IsShort, f.Short = true, apdu[1]&0x3F
	} else {
		f.Data = append([]byte(nil), apdu[2:]...)
		if top != GroupValueResponse && top != GroupValueWrite && top != GroupValueRead {
			// Point-to-point services keep their six low bits (a count, a
			// channel, a descriptor type) next to the data.
			f.Short = apdu[1] & 0x3F
		}
	}
	return f, nil
}

// Busmon is an L_Busmon.ind: a frame as seen on the medium, with its
// status and timestamp from the additional information when present.
type Busmon struct {
	AddInfo []byte
	// Raw is the frame as on the medium (TP1: control field to checksum).
	Raw []byte
	// Status is the busmonitor status octet (additional information type
	// 0x03), Timestamp the relative timestamp (type 0x04), when present.
	Status    byte
	Timestamp uint16
}

// ParseBusmon decodes an L_Busmon.ind cEMI frame.
func ParseBusmon(b []byte) (Busmon, error) {
	if len(b) < 2 || b[0] != LBusmonInd {
		return Busmon{}, errors.New("cemi: not an L_Busmon.ind frame")
	}
	ai := int(b[1])
	if len(b) < 2+ai {
		return Busmon{}, errors.New("cemi: L_Busmon.ind too short")
	}
	m := Busmon{AddInfo: append([]byte(nil), b[2:2+ai]...), Raw: append([]byte(nil), b[2+ai:]...)}
	for x := m.AddInfo; len(x) >= 2; {
		typ, n := x[0], int(x[1])
		if len(x) < 2+n {
			break
		}
		switch {
		case typ == 0x03 && n == 1:
			m.Status = x[2]
		case typ == 0x04 && n == 2:
			m.Timestamp = binary.BigEndian.Uint16(x[2:4])
		}
		x = x[2+n:]
	}
	return m, nil
}
