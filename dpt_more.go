// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
)

// The datapoint types added in v0.2.0 (KNX Standard volume 3 part 7
// section 2): 2.x, 3.x, 4.x, 5.x (every sub), 6.x, 8.x, 10.001, 11.001,
// 12.x, 17.001, 18.001, 19.001, 21.x, 29.x, 232.600 and 251.600. Values are
// JSON-friendly: numbers as float64, times and dates as strings, colours
// as "#RRGGBB" / "#RRGGBBWW", and the compound control types as maps.

// moreMains are the main numbers handled here.
var moreMains = map[int]int{ // main → data bytes
	2: 1, 3: 1, 4: 1, 6: 1, 8: 2, 10: 3, 11: 3, 12: 4, 17: 1, 18: 1, 19: 8, 21: 1, 29: 8, 232: 3, 251: 6,
}

// scales of the 7.x and 8.x types whose raw value is in steps other than 1.
var scales = map[DPT]float64{
	{7, 3}: 10, {7, 4}: 100, {8, 3}: 10, {8, 4}: 100, {8, 10}: 0.01,
}

func init() {
	for d, u := range map[DPT]string{
		{6, 1}: "%", {8, 2}: "ms", {8, 3}: "ms", {8, 4}: "ms", {8, 5}: "s", {8, 6}: "min", {8, 7}: "h",
		{8, 10}: "%", {8, 11}: "deg", {8, 12}: "m", {12, 100}: "s", {12, 101}: "min", {12, 102}: "h",
		{12, 1200}: "l", {12, 1201}: "m3", {29, 10}: "Wh", {29, 11}: "VAh", {29, 12}: "varh",
	} {
		units[d] = u
	}
}

func moreSupported(d DPT) bool {
	switch d.Main {
	case 10, 11, 17, 18, 19:
		return d.Sub == 1
	case 232:
		return d.Sub == 600
	case 251:
		return d.Sub == 600
	}
	_, ok := moreMains[d.Main]
	return ok
}

func scaled(d DPT, raw float64) float64 {
	if s, ok := scales[d]; ok {
		return math.Round(raw*s*100) / 100
	}
	return raw
}

func unscaled(d DPT, v float64) float64 {
	if s, ok := scales[d]; ok {
		return math.Round(v / s)
	}
	return v
}

func decodeMore(d DPT, b []byte) (any, error) {
	if need := moreMains[d.Main]; len(b) < need {
		return nil, fmt.Errorf("DPT %s needs %d data bytes, got %d", d, need, len(b))
	}
	switch d.Main {
	case 2:
		return map[string]any{"control": b[0]&0x02 != 0, "value": b[0]&0x01 != 0}, nil
	case 3:
		return map[string]any{"control": b[0]&0x08 != 0, "step": float64(b[0] & 0x07)}, nil
	case 4:
		return latin1(b[:1]), nil
	case 6:
		return float64(int8(b[0])), nil
	case 8:
		return scaled(d, float64(int16(binary.BigEndian.Uint16(b)))), nil
	case 10:
		day := b[0] >> 5
		s := fmt.Sprintf("%02d:%02d:%02d", b[0]&0x1F, b[1]&0x3F, b[2]&0x3F)
		if day != 0 {
			s = time.Weekday(day % 7).String()[:3] + " " + s
		}
		return s, nil
	case 11:
		y := int(b[2] & 0x7F)
		if y >= 90 {
			y += 1900
		} else {
			y += 2000
		}
		return fmt.Sprintf("%04d-%02d-%02d", y, b[1]&0x0F, b[0]&0x1F), nil
	case 12:
		return float64(binary.BigEndian.Uint32(b)), nil
	case 17:
		return float64(b[0] & 0x3F), nil
	case 18:
		return map[string]any{"learn": b[0]&0x80 != 0, "scene": float64(b[0] & 0x3F)}, nil
	case 19:
		return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", 1900+int(b[0]), b[1]&0x0F, b[2]&0x1F, b[3]&0x1F, b[4]&0x3F, b[5]&0x3F), nil
	case 21:
		return float64(b[0]), nil
	case 29:
		return float64(int64(binary.BigEndian.Uint64(b))), nil
	case 232:
		return "#" + strings.ToUpper(hex.EncodeToString(b[:3])), nil
	case 251:
		return "#" + strings.ToUpper(hex.EncodeToString(b[:4])), nil
	}
	return nil, fmt.Errorf("datapoint type %s is not supported", d)
}

func boolOf(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case float64:
		return x != 0, x == 0 || x == 1
	}
	return false, false
}

func encodeMore(d DPT, v any) ([]byte, error) {
	switch d.Main {
	case 2:
		if m, ok := v.(map[string]any); ok {
			c, ok1 := boolOf(m["control"])
			val, ok2 := boolOf(m["value"])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("DPT %s takes {\"control\": bool, \"value\": bool}", d)
			}
			var b byte
			if c {
				b |= 2
			}
			if val {
				b |= 1
			}
			return []byte{b}, nil
		}
	case 3:
		if m, ok := v.(map[string]any); ok {
			c, ok1 := boolOf(m["control"])
			step, err := number(m["step"])
			if !ok1 || err != nil || step < 0 || step > 7 || step != math.Trunc(step) {
				return nil, fmt.Errorf("DPT %s takes {\"control\": bool, \"step\": 0-7}", d)
			}
			b := byte(step)
			if c {
				b |= 8
			}
			return []byte{b}, nil
		}
	case 4:
		s, ok := v.(string)
		r := []rune(s)
		if !ok || len(r) != 1 || r[0] > 0xFF || (d.Sub == 1 && r[0] > 0x7F) {
			return nil, fmt.Errorf("DPT %s takes one character", d)
		}
		return []byte{byte(r[0])}, nil
	case 10:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("DPT 10.001 takes a time such as \"14:30:00\" or \"Mon 14:30:00\"")
		}
		var day byte
		if f := strings.Fields(s); len(f) == 2 {
			for i := 0; i < 7; i++ {
				if strings.EqualFold(time.Weekday(i).String()[:3], f[0][:min(3, len(f[0]))]) {
					day = byte(i)
					if i == 0 {
						day = 7
					}
				}
			}
			if day == 0 {
				return nil, fmt.Errorf("DPT 10.001: day %q not known", f[0])
			}
			s = f[1]
		}
		var h, m, sec int
		if _, err := fmt.Sscanf(s, "%d:%d:%d", &h, &m, &sec); err != nil || h > 23 || m > 59 || sec > 59 || h < 0 || m < 0 || sec < 0 {
			return nil, fmt.Errorf("DPT 10.001 takes a time such as \"14:30:00\"")
		}
		return []byte{day<<5 | byte(h), byte(m), byte(sec)}, nil
	case 11:
		s, _ := v.(string)
		t, err := time.Parse("2006-01-02", s)
		if err != nil || t.Year() < 1990 || t.Year() > 2089 {
			return nil, fmt.Errorf("DPT 11.001 takes a date from 1990-01-01 to 2089-12-31")
		}
		return []byte{byte(t.Day()), byte(t.Month()), byte(t.Year() % 100)}, nil
	case 18:
		if m, ok := v.(map[string]any); ok {
			l, ok1 := boolOf(m["learn"])
			sc, err := number(m["scene"])
			if !ok1 || err != nil || sc < 0 || sc > 63 || sc != math.Trunc(sc) {
				return nil, fmt.Errorf("DPT 18.001 takes {\"learn\": bool, \"scene\": 0-63}")
			}
			b := byte(sc)
			if l {
				b |= 0x80
			}
			return []byte{b}, nil
		}
	case 19:
		s, _ := v.(string)
		t, err := time.Parse("2006-01-02T15:04:05", s)
		if err != nil || t.Year() < 1900 || t.Year() > 2155 {
			return nil, fmt.Errorf("DPT 19.001 takes a date and time such as \"2026-10-11T14:30:00\"")
		}
		wd := byte(t.Weekday())
		if wd == 0 {
			wd = 7
		}
		// Flags: working day, daylight saving and clock quality not
		// given (bits "no WD" set).
		return []byte{byte(t.Year() - 1900), byte(t.Month()), byte(t.Day()), wd<<5 | byte(t.Hour()), byte(t.Minute()), byte(t.Second()), 0x20, 0x00}, nil
	case 232, 251:
		s, _ := v.(string)
		n := 3
		if d.Main == 251 {
			n = 4
		}
		b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "#"))
		if err != nil || len(b) != n {
			return nil, fmt.Errorf("DPT %s takes a colour such as \"#%s\"", d, strings.Repeat("FF", n))
		}
		if d.Main == 251 {
			return append(b, 0x00, 0x0F), nil // all four channels valid
		}
		return b, nil
	}
	f, err := number(v)
	if err != nil {
		return nil, fmt.Errorf("DPT %s takes a number: %w", d, err)
	}
	raw := unscaled(d, f)
	if raw != math.Trunc(raw) {
		return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
	}
	switch d.Main {
	case 2:
		if raw < 0 || raw > 3 {
			return nil, fmt.Errorf("DPT %s: %v: %w (0-3)", d, v, errRange)
		}
		return []byte{byte(raw)}, nil
	case 3:
		if raw < 0 || raw > 15 {
			return nil, fmt.Errorf("DPT %s: %v: %w (0-15)", d, v, errRange)
		}
		return []byte{byte(raw)}, nil
	case 6:
		if raw < math.MinInt8 || raw > math.MaxInt8 {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return []byte{byte(int8(raw))}, nil
	case 8:
		if raw < math.MinInt16 || raw > math.MaxInt16 {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return binary.BigEndian.AppendUint16(nil, uint16(int16(raw))), nil
	case 12:
		if raw < 0 || raw > math.MaxUint32 {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return binary.BigEndian.AppendUint32(nil, uint32(raw)), nil
	case 17:
		if raw < 0 || raw > 63 {
			return nil, fmt.Errorf("DPT %s: %v: %w (0-63)", d, v, errRange)
		}
		return []byte{byte(raw)}, nil
	case 18, 21:
		if raw < 0 || raw > 255 {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return []byte{byte(raw)}, nil
	case 29:
		if raw < -9.2e18 || raw > 9.2e18 {
			return nil, fmt.Errorf("DPT %s: %v: %w", d, v, errRange)
		}
		return binary.BigEndian.AppendUint64(nil, uint64(int64(raw))), nil
	}
	return nil, fmt.Errorf("DPT %s: %v is not a value of this type", d, v)
}
