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
)

// Application-layer services on group addresses (10-bit APCI values).
const (
	GroupValueRead     uint16 = 0x000
	GroupValueResponse uint16 = 0x040
	GroupValueWrite    uint16 = 0x080
)

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

// Encode writes the cEMI frame.
func (f LData) Encode() []byte {
	b := []byte{f.Code, byte(len(f.AddInfo))}
	b = append(b, f.AddInfo...)
	ctrl2 := f.Ctrl2
	if f.GroupTarget {
		ctrl2 |= ctrl2GroupDest
	}
	b = append(b, f.Ctrl1, ctrl2)
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Dest)
	apdu := []byte{f.TPCI&0xFC | byte(f.APCI>>8)&0x03, byte(f.APCI)}
	if f.IsShort {
		apdu[1] |= f.Short & 0x3F
	} else {
		apdu = append(apdu, f.Data...)
	}
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
	f.TPCI = apdu[0] & 0xFC
	if n == 0 {
		// A bare TPCI (transport control, no application data).
		return f, nil
	}
	f.APCI = uint16(apdu[0]&0x03)<<8 | uint16(apdu[1]&0xC0)
	if n == 1 {
		f.IsShort, f.Short = true, apdu[1]&0x3F
	} else {
		f.Data = append([]byte(nil), apdu[2:]...)
	}
	return f, nil
}
