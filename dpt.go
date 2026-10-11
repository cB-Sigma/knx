package knx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Datapoint types (KNX Standard volume 3 part 7 section 2): the encoding of
// a group object's value. A DPT is "main.sub"; the main number fixes the
// encoding, the sub number the meaning and unit.

// DPT is a parsed datapoint type.
type DPT struct {
	Main, Sub int
}

// String formats the type as "main.sub" with a three-digit sub number,
// such as "9.001".
func (d DPT) String() string { return fmt.Sprintf("%d.%03d", d.Main, d.Sub) }

// ParseDPT reads "9.001", "9.1", "DPT9.001" or "dpst-9-1".
func ParseDPT(s string) (DPT, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "dpt")
	t = strings.TrimPrefix(t, "dpst-")
	t = strings.TrimPrefix(t, "-")
	t = strings.ReplaceAll(t, "-", ".")
	mainS, subS, _ := strings.Cut(t, ".")
	m, err := strconv.Atoi(mainS)
	if err != nil {
		return DPT{}, fmt.Errorf("datapoint type %q is not main.sub such as 9.001", s)
	}
	sub := 0
	if subS != "" {
		if sub, err = strconv.Atoi(subS); err != nil {
			return DPT{}, fmt.Errorf("datapoint type %q is not main.sub such as 9.001", s)
		}
	}
	d := DPT{Main: m, Sub: sub}
	if !d.Supported() {
		return d, fmt.Errorf("%w: %s (decoded: %s)", ErrDPTRaw, d, DecodedDPTs)
	}
	return d, nil
}

// DecodedDPTs lists the datapoint types this package encodes and decodes.
const DecodedDPTs = "1.x, 2.x, 3.x, 4.x, 5.x, 6.x, 7.x, 8.x, 9.x, 10.001, 11.001, 12.x, 13.x, 14.x, 16.000, 16.001, 17.001, 18.001, 19.001, 20.x, 21.x, 29.x, 232.600, 251.600"

// ErrDPTRaw is ParseDPT's error for a well-formed datapoint type this
// package does not decode; the DPT it returns with it still works, with
// raw values (Decode gives the application data as hex, Encode takes hex).
var ErrDPTRaw = errors.New("datapoint type not decoded; its values are raw hex")

// Supported reports whether this package encodes the DPT.
func (d DPT) Supported() bool {
	switch d.Main {
	case 1, 5, 7, 9, 13, 14, 20:
		return true
	case 16:
		return d.Sub == 0 || d.Sub == 1
	}
	return moreSupported(d)
}

// Short reports whether the value travels in the 6 bits of the APCI octet
// (the types of at most 6 bits: 1.x, 2.x, 3.x, 23.x).
func (d DPT) Short() bool { return d.Main == 1 || d.Main == 2 || d.Main == 3 || d.Main == 23 }

// units of the sub types we know, as UCUM-style codes.
var units = map[DPT]string{
	{5, 1}: "%", {5, 3}: "deg", {5, 4}: "%",
	{7, 2}: "ms", {7, 3}: "ms", {7, 4}: "ms", {7, 5}: "s", {7, 6}: "min", {7, 7}: "h",
	{7, 11}: "mm", {7, 12}: "mA", {7, 13}: "lx", {7, 600}: "K",
	{9, 1}: "Cel", {9, 2}: "K", {9, 3}: "K/h", {9, 4}: "lx", {9, 5}: "m/s", {9, 6}: "Pa",
	{9, 7}: "%", {9, 8}: "ppm", {9, 10}: "s", {9, 11}: "ms", {9, 20}: "mV", {9, 21}: "mA",
	{9, 22}: "W/m2", {9, 24}: "kW", {9, 25}: "l/h", {9, 26}: "l/m2", {9, 27}: "[degF]", {9, 28}: "km/h",
	{9, 29}: "g/m3", {9, 30}: "ug/m3",
	{13, 2}: "m3/h", {13, 10}: "Wh", {13, 11}: "VAh", {13, 12}: "varh", {13, 13}: "kWh",
	{13, 14}: "kVAh", {13, 15}: "kvarh", {13, 16}: "MWh", {13, 100}: "s",
	{14, 7}: "deg", {14, 19}: "A", {14, 27}: "V", {14, 31}: "J", {14, 33}: "Hz", {14, 54}: "rad",
	{14, 56}: "W", {14, 57}: "1", {14, 58}: "Pa", {14, 65}: "m/s", {14, 68}: "Cel", {14, 69}: "K",
	{14, 76}: "m3", {14, 77}: "m3/s",
}

// Unit is the DPT's unit, or "" when it has none (or we do not know it).
func (d DPT) Unit() string { return units[d] }

// HVAC modes of DPT 20.102.
var hvacModes = []string{"auto", "comfort", "standby", "economy", "building-protection"}

var errRange = errors.New("value out of range for the datapoint type")

// Decode turns application data (as LData.Value returns it) into a value:
// bool for 1.x, float64 for numbers, string for 16.x.
func (d DPT) Decode(b []byte) (any, error) {
	if !d.Supported() {
		return strings.ToUpper(hex.EncodeToString(b)), nil
	}
	if _, ok := moreMains[d.Main]; ok {
		return decodeMore(d, b)
	}
	need := map[int]int{1: 1, 5: 1, 7: 2, 9: 2, 13: 4, 14: 4, 16: 14, 20: 1}[d.Main]
	if len(b) < need {
		return nil, fmt.Errorf("DPT %s needs %d data bytes, got %d", d, need, len(b))
	}
	switch d.Main {
	case 1:
		return b[0]&0x01 == 1, nil
	case 5:
		switch d.Sub {
		case 1:
			return math.Round(float64(b[0])*100/255*100) / 100, nil
		case 3:
			return math.Round(float64(b[0])*360/255*100) / 100, nil
		default:
			return float64(b[0]), nil
		}
	case 7:
		return scaled(d, float64(binary.BigEndian.Uint16(b))), nil
	case 9:
		return DecodeFloat16(binary.BigEndian.Uint16(b))
	case 13:
		return float64(int32(binary.BigEndian.Uint32(b))), nil
	case 14:
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
	case 16:
		s := b[:14]
		for i, c := range s {
			if c == 0 {
				s = s[:i]
				break
			}
		}
		return latin1(s), nil
	case 20:
		return float64(b[0]), nil
	}
	return nil, fmt.Errorf("datapoint type %s is not supported", d)
}

// Encode turns a JSON value (bool, number, numeric or named string) into
// application data.
func (d DPT) Encode(v any) ([]byte, error) {
	if !d.Supported() {
		// Raw: hex text, or a number 0–255 for one octet.
		switch x := v.(type) {
		case string:
			b, err := hex.DecodeString(strings.ReplaceAll(x, " ", ""))
			if err != nil || len(b) == 0 {
				return nil, fmt.Errorf("DPT %s is sent raw: give the value as hex, such as \"0A\"", d)
			}
			return b, nil
		case float64:
			if x >= 0 && x <= 255 && x == math.Trunc(x) {
				return []byte{byte(x)}, nil
			}
		}
		return nil, fmt.Errorf("DPT %s is sent raw: give the value as hex, such as \"0A\", or a number 0 to 255", d)
	}
	if _, ok := moreMains[d.Main]; ok {
		return encodeMore(d, v)
	}
	switch d.Main {
	case 1:
		switch x := v.(type) {
		case bool:
			if x {
				return []byte{1}, nil
			}
			return []byte{0}, nil
		case float64:
			if x == 0 || x == 1 {
				return []byte{byte(x)}, nil
			}
		case string:
			switch strings.ToLower(x) {
			case "on", "true", "1", "up", "open", "start", "enable":
				return []byte{1}, nil
			case "off", "false", "0", "down", "close", "stop", "disable":
				return []byte{0}, nil
			}
		}
		return nil, fmt.Errorf("DPT %s takes true or false, got %v", d, v)
	case 16:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("DPT %s takes a string", d)
		}
		out := make([]byte, 14)
		i := 0
		for _, r := range s {
			if i == 14 {
				return nil, fmt.Errorf("DPT %s holds at most 14 characters", d)
			}
			if (d.Sub == 0 && r > 0x7F) || r > 0xFF {
				return nil, fmt.Errorf("DPT %s cannot hold %q", d, r)
			}
			out[i] = byte(r)
			i++
		}
		return out, nil
	case 20:
		if s, ok := v.(string); ok && d.Sub == 102 {
			for i, m := range hvacModes {
				if strings.EqualFold(s, m) {
					return []byte{byte(i)}, nil
				}
			}
			return nil, fmt.Errorf("DPT 20.102 takes %s or 0-4", strings.Join(hvacModes, ", "))
		}
	}
	f, err := number(v)
	if err != nil {
		return nil, fmt.Errorf("DPT %s takes a number: %w", d, err)
	}
	switch d.Main {
	case 5:
		raw := f
		switch d.Sub {
		case 1:
			raw = math.Round(f * 255 / 100)
		case 3:
			raw = math.Round(f * 255 / 360)
		}
		if f < 0 || raw > 255 || raw != math.Trunc(raw) {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return []byte{byte(raw)}, nil
	case 7:
		f = unscaled(d, f)
		if f < 0 || f > math.MaxUint16 || f != math.Trunc(f) {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return binary.BigEndian.AppendUint16(nil, uint16(f)), nil
	case 9:
		w, err := EncodeFloat16(f)
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint16(nil, w), nil
	case 13:
		if f < math.MinInt32 || f > math.MaxInt32 || f != math.Trunc(f) {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return binary.BigEndian.AppendUint32(nil, uint32(int32(f))), nil
	case 14:
		return binary.BigEndian.AppendUint32(nil, math.Float32bits(float32(f))), nil
	case 20:
		if f < 0 || f > 255 || f != math.Trunc(f) {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return []byte{byte(f)}, nil
	}
	return nil, fmt.Errorf("datapoint type %s is not supported", d)
}

func number(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	}
	return 0, fmt.Errorf("%v is not a number", v)
}

// KNX 2-byte float (DPT 9): value = 0.01 × M × 2^E with M a 12-bit two's
// complement mantissa (sign in bit 15, magnitude bits 10..0) and E a 4-bit
// exponent in bits 14..11. 0x7FFF means "invalid".

// ErrInvalidFloat16 is the decoded 0x7FFF "invalid data" value.
var ErrInvalidFloat16 = errors.New("DPT 9: the device reports invalid data (0x7FFF)")

// DecodeFloat16 decodes a DPT 9 word.
func DecodeFloat16(w uint16) (float64, error) {
	if w == 0x7FFF {
		return 0, ErrInvalidFloat16
	}
	e := int(w>>11) & 0x0F
	m := int(w & 0x07FF)
	if w&0x8000 != 0 {
		m -= 2048
	}
	v := 0.01 * float64(m) * float64(int(1)<<e)
	return math.Round(v*100) / 100, nil
}

// EncodeFloat16 encodes a value as a DPT 9 word, using the smallest
// exponent that fits the mantissa.
func EncodeFloat16(v float64) (uint16, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("DPT 9: %v: %w", v, errRange)
	}
	m := math.Round(v * 100)
	e := 0
	for m < -2048 || m > 2047 {
		e++
		if e > 15 {
			return 0, fmt.Errorf("DPT 9: %v: %w (-671088.64 to 670760.96)", v, errRange)
		}
		m = math.Round(v * 100 / float64(int(1)<<e))
	}
	mi := int(m)
	w := uint16(e) << 11
	if mi < 0 {
		w |= 0x8000
		mi += 2048
	}
	w |= uint16(mi) & 0x07FF
	if w == 0x7FFF {
		return 0, fmt.Errorf("DPT 9: %v: %w (0x7FFF is reserved for invalid data)", v, errRange)
	}
	return w, nil
}
