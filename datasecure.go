// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// KNX Data Secure (KNX Standard volume 3 part 3 clause 7, the secure
// application layer; AN158): group telegrams protected end to end with a
// group key, whatever medium carries them. A secured frame carries the APCI
// SecureService (0x3F1), then the security control field (SCF), a 48-bit
// sequence number, the protected APDU and a 4-octet MAC.
//
// With the CCM encryption algorithm the plain APDU is encrypted and the MAC
// is a CBC-MAC over block 0 (sequence, source, destination, 0x00, the
// address-type and extended-format bits of control field 2, the TPCI octet
// with the secure APCI's high bits, 0xF1, 0x00, the APDU length), the
// length and value of the associated data (the SCF) and the APDU, cut to 4
// octets; counter 0 (sequence, source, destination, 00 00 00 00 01 00)
// starts a CTR key stream that encrypts the MAC and then, continuing in the
// same stream, the APDU. With the authentication-only algorithm the APDU
// travels in clear and is part of the associated data. These facts are as
// publicly documented by the MIT-licensed xknx project
// (xknx/secure/data_secure.py, data_secure_asdu.py); no code was taken.
//
// Each receiver keeps, per sender, the last sequence number it accepted and
// takes only higher ones; each sender counts up. Only group communication
// with group keys is handled; point-to-point frames protected with a tool
// key pass through unchanged (Open reports them with ErrDataSecure).

// Security control field values.
const (
	SCFAuthOnly   byte = 0x00 // CCM, authentication only
	SCFEncrypted  byte = 0x10 // CCM, authentication and encryption
	scfToolAccess byte = 0x80
	scfSystemBC   byte = 0x08
	scfService    byte = 0x07 // 0 = S-A_Data, 2/3 = sync request/response
	dsMACLen           = 4
)

// ErrDataSecure marks a KNX Data Secure frame that was refused: unknown
// sender or group, an old sequence number, a failed MAC, or a plain frame
// for a group that is secured.
var ErrDataSecure = errors.New("knx data secure")

// DataSecureOptions configure a DataSecure.
type DataSecureOptions struct {
	// GroupKeys are the 16-byte keys of the secured group addresses.
	GroupKeys map[GroupAddress][]byte
	// Senders are the individual addresses allowed to send secured
	// frames, with the last sequence number accepted from each (0 when
	// unknown).
	Senders map[IndividualAddress]uint64
	// Sequence is the first sequence number to send with (default: the
	// milliseconds since 2018-01-05, which keeps rising across restarts as
	// long as the clock is right).
	Sequence uint64
	// AuthOnly sends these groups with authentication only (the APDU in
	// clear); others are encrypted.
	AuthOnly map[GroupAddress]bool
}

// DataSecure seals outgoing and opens incoming group frames. It is safe
// for concurrent use.
type DataSecure struct {
	mu       sync.Mutex
	keys     map[GroupAddress][]byte
	senders  map[IndividualAddress]uint64
	authOnly map[GroupAddress]bool
	next     uint64
}

var dsEpoch = time.Date(2018, 1, 5, 0, 0, 0, 0, time.UTC)

const dsSeqMax = 1<<48 - 1

// NewDataSecure checks the keys and returns a DataSecure.
func NewDataSecure(o DataSecureOptions) (*DataSecure, error) {
	d := &DataSecure{keys: map[GroupAddress][]byte{}, senders: map[IndividualAddress]uint64{}, authOnly: map[GroupAddress]bool{}}
	for ga, k := range o.GroupKeys {
		if len(k) != 16 {
			return nil, fmt.Errorf("%w: the key of %s has %d bytes, not 16", ErrDataSecure, ga, len(k))
		}
		d.keys[ga] = append([]byte(nil), k...)
	}
	for ia, s := range o.Senders {
		d.senders[ia] = s
	}
	for ga, v := range o.AuthOnly {
		d.authOnly[ga] = v
	}
	d.next = o.Sequence
	if d.next == 0 {
		d.next = uint64(time.Since(dsEpoch) / time.Millisecond)
	}
	if d.next == 0 || d.next > dsSeqMax {
		return nil, fmt.Errorf("%w: first sequence number %d out of range (is the clock set?)", ErrDataSecure, d.next)
	}
	return d, nil
}

// Secured reports whether a group address has a key.
func (d *DataSecure) Secured(ga GroupAddress) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.keys[ga] != nil
}

// NextSequence is the sequence number the next sealed frame gets; persist
// it to start from it again.
func (d *DataSecure) NextSequence() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.next
}

// LastSequence is the last sequence number accepted from a sender.
func (d *DataSecure) LastSequence(ia IndividualAddress) (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.senders[ia]
	return s, ok
}

// Seal protects a frame to a secured group address; frames to other
// destinations come back unchanged. The frame's Source must be set (it is
// part of the MAC).
func (d *DataSecure) Seal(f LData) (LData, error) {
	if !f.GroupTarget || f.Control() {
		return f, nil
	}
	d.mu.Lock()
	key := d.keys[f.Group()]
	if key == nil {
		d.mu.Unlock()
		return f, nil
	}
	if d.next > dsSeqMax {
		d.mu.Unlock()
		return f, fmt.Errorf("%w: the sending sequence number is exhausted", ErrDataSecure)
	}
	seq := d.next
	d.next++
	scf := SCFEncrypted
	if d.authOnly[f.Group()] {
		scf = SCFAuthOnly
	}
	d.mu.Unlock()
	return SealData(key, scf, seq, f), nil
}

// Open checks and unwraps a secured group frame. A plain frame to a group
// without a key comes back unchanged; a plain frame to a secured group, a
// secured frame from an unknown sender or for an unknown group, an old
// sequence number or a wrong MAC give ErrDataSecure. Point-to-point and
// tool-key frames are refused with ErrDataSecure too.
func (d *DataSecure) Open(f LData) (LData, error) {
	if f.APCI != SecureService || f.Control() {
		if f.GroupTarget && d.Secured(f.Group()) && !f.Control() {
			return f, fmt.Errorf("%w: plain frame for the secured group %s from %s", ErrDataSecure, f.Group(), f.Source)
		}
		return f, nil
	}
	if len(f.Data) < 1 {
		return f, fmt.Errorf("%w: secured frame without a control field", ErrDataSecure)
	}
	scf := f.Data[0]
	if scf&scfService != 0 {
		return f, fmt.Errorf("%w: secure service %d is not S-A_Data", ErrDataSecure, scf&scfService)
	}
	if scf&(scfToolAccess|scfSystemBC) != 0 || !f.GroupTarget {
		return f, fmt.Errorf("%w: tool-key, system broadcast and point-to-point frames are not handled", ErrDataSecure)
	}
	d.mu.Lock()
	key := d.keys[f.Group()]
	last, known := d.senders[f.Source]
	d.mu.Unlock()
	if key == nil {
		return f, fmt.Errorf("%w: no key for %s", ErrDataSecure, f.Group())
	}
	if !known {
		return f, fmt.Errorf("%w: %s is not a known secure sender", ErrDataSecure, f.Source)
	}
	plain, seq, err := OpenData(key, f)
	if err != nil {
		return f, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if last = d.senders[f.Source]; seq <= last {
		return f, fmt.Errorf("%w: sequence number %d from %s is not above %d", ErrDataSecure, seq, f.Source, last)
	}
	d.senders[f.Source] = seq
	return plain, nil
}

// dsAddrs is source and destination as they enter block 0 and counter 0.
func dsAddrs(f LData) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(f.Source))
	return binary.BigEndian.AppendUint16(b, f.Dest)
}

func dsBlock0(seq []byte, f LData, n int) []byte {
	ctrl2 := f.Ctrl2
	if f.GroupTarget {
		ctrl2 |= ctrl2GroupDest
	}
	b := append(append([]byte(nil), seq...), dsAddrs(f)...)
	return append(b, 0, ctrl2&0x8F, f.TPCI&0xFC|byte(SecureService>>8), byte(SecureService&0xFF), 0, byte(n))
}

func dsCounter0(seq []byte, f LData) []byte {
	b := append(append([]byte(nil), seq...), dsAddrs(f)...)
	return append(b, 0, 0, 0, 0, 1, 0)
}

func seq48(v uint64) []byte {
	return []byte{byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// SealData protects one frame with key, security control field scf
// (SCFEncrypted or SCFAuthOnly) and sequence number seq. Most programs use
// DataSecure.Seal, which keeps the sequence.
func SealData(key []byte, scf byte, seq uint64, f LData) LData {
	plain := f
	plain.TPCI = 0
	apdu := plain.apdu() // the plain APDU with a zero TPCI
	sq := seq48(seq)
	blk := newBlock(key)
	var body []byte
	if scf&0x70 == SCFEncrypted {
		mac := cbcMAC(blk, dsBlock0(sq, f, len(apdu)), []byte{scf}, apdu)[:dsMACLen]
		encMAC, enc := ctrXOR(blk, dsCounter0(sq, f), mac, apdu)
		body = append(append(append([]byte{scf}, sq...), enc...), encMAC...)
	} else {
		mac := cbcMAC(blk, dsBlock0(sq, f, 0), append([]byte{scf}, apdu...), nil)[:dsMACLen]
		body = append(append(append([]byte{scf}, sq...), apdu...), mac...)
	}
	out := f
	out.APCI, out.IsShort, out.Short, out.Data = SecureService, false, 0, body
	return out
}

// OpenData checks one secured frame with key and returns the plain frame
// and its sequence number (without the per-sender sequence check that
// DataSecure.Open adds).
func OpenData(key []byte, f LData) (LData, uint64, error) {
	if f.APCI != SecureService || len(f.Data) < 1+6+dsMACLen {
		return f, 0, fmt.Errorf("%w: not a secured frame", ErrDataSecure)
	}
	scf := f.Data[0]
	sq := f.Data[1:7]
	seq := binary.BigEndian.Uint64(append([]byte{0, 0}, sq...))
	payload := f.Data[7 : len(f.Data)-dsMACLen]
	gotMAC := f.Data[len(f.Data)-dsMACLen:]
	blk := newBlock(key)
	var apdu []byte
	switch scf & 0x70 {
	case SCFEncrypted:
		mac, plain := ctrXOR(blk, dsCounter0(sq, f), gotMAC, payload)
		want := cbcMAC(blk, dsBlock0(sq, f, len(plain)), []byte{scf}, plain)[:dsMACLen]
		if !CheckMAC(mac, want) {
			return f, 0, fmt.Errorf("%w: MAC check failed for %s from %s", ErrDataSecure, GroupAddress(f.Dest), f.Source)
		}
		apdu = plain
	case SCFAuthOnly:
		want := cbcMAC(blk, dsBlock0(sq, f, 0), append([]byte{scf}, payload...), nil)[:dsMACLen]
		if !CheckMAC(gotMAC, want) {
			return f, 0, fmt.Errorf("%w: MAC check failed for %s from %s", ErrDataSecure, GroupAddress(f.Dest), f.Source)
		}
		apdu = payload
	default:
		return f, 0, fmt.Errorf("%w: security algorithm %#x not known", ErrDataSecure, scf&0x70)
	}
	if len(apdu) < 2 {
		return f, 0, fmt.Errorf("%w: secured APDU shorter than two octets", ErrDataSecure)
	}
	// Re-read the frame with the plain APDU in place of the secured one.
	raw := f
	raw.APCI, raw.IsShort, raw.Short, raw.Data = 0, false, 0, nil
	enc := raw.Encode()
	hdr := enc[:len(enc)-3] // up to and without the length octet and the two APCI octets
	hdr = append(hdr, byte(len(apdu)-1), f.TPCI&0xFC|apdu[0]&0x03)
	hdr = append(hdr, apdu[1:]...)
	out, err := ParseLData(hdr)
	if err != nil {
		return f, 0, fmt.Errorf("%w: %v", ErrDataSecure, err)
	}
	out.Ctrl1 = f.Ctrl1
	return out, seq, nil
}
