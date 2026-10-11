package knx

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Password-protected ETS projects keep the project files in an inner zip
// whose entries are encrypted. ETS 4 and 5 use the traditional PKWARE
// ("ZipCrypto") stream cipher with the project password; ETS 6 uses WinZip
// AES (compression method 99, extra field 0x9901) with a password derived
// from the project password (etsZipPassword). Go's archive/zip reads
// neither, so both are implemented here from the published zip format
// descriptions (PKWARE APPNOTE section 6.1; WinZip "AES Encryption
// Information"), reading each entry's raw bytes with OpenRaw.

// ErrZipPassword is returned when an encrypted entry's password check fails.
var ErrZipPassword = errors.New("the project password is wrong")

const (
	zipMethodAES  = 99
	zipExtraAES   = 0x9901
	zipFlagCrypt  = 0x1
	zipFlagDescr  = 0x8
	zipAESAuthLen = 10
)

// readZipEntry returns an entry's uncompressed bytes, decrypting it with
// password when it is encrypted.
func readZipEntry(f *zip.File, password []byte) ([]byte, error) {
	if f.Flags&zipFlagCrypt == 0 && f.Method != zipMethodAES {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	if len(password) == 0 {
		return nil, ErrZipPassword
	}
	r, err := f.OpenRaw()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	method := f.Method
	var plain []byte
	if f.Method == zipMethodAES {
		if plain, method, err = winzipAESDecrypt(f, raw, password); err != nil {
			return nil, err
		}
	} else {
		check := byte(f.CRC32 >> 24)
		if f.Flags&zipFlagDescr != 0 {
			check = byte(f.ModifiedTime >> 8)
		}
		if plain, err = zipCryptoDecrypt(raw, password, check); err != nil {
			return nil, err
		}
	}
	var out []byte
	switch method {
	case zip.Store:
		out = plain
	case zip.Deflate:
		if out, err = io.ReadAll(flate.NewReader(bytes.NewReader(plain))); err != nil {
			return nil, fmt.Errorf("%s: %w (a wrong password can cause this)", f.Name, err)
		}
	default:
		return nil, fmt.Errorf("%s: compression method %d is not supported", f.Name, method)
	}
	// AE-2 entries carry no CRC (it is zero); AE-1 and ZipCrypto entries do.
	if f.CRC32 != 0 && crc32.ChecksumIEEE(out) != f.CRC32 {
		return nil, fmt.Errorf("%s: checksum mismatch: %w", f.Name, ErrZipPassword)
	}
	return out, nil
}

// zipKeys is the traditional PKWARE cipher state.
type zipKeys [3]uint32

func newZipKeys(password []byte) *zipKeys {
	k := &zipKeys{0x12345678, 0x23456789, 0x34567890}
	for _, c := range password {
		k.update(c)
	}
	return k
}

func crcByte(crc uint32, b byte) uint32 {
	return crc32.IEEETable[byte(crc)^b] ^ crc>>8
}

func (k *zipKeys) update(c byte) {
	k[0] = crcByte(k[0], c)
	k[1] = (k[1]+k[0]&0xFF)*134775813 + 1
	k[2] = crcByte(k[2], byte(k[1]>>24))
}

func (k *zipKeys) stream() byte {
	t := uint16(k[2] | 2)
	return byte((t * (t ^ 1)) >> 8)
}

func (k *zipKeys) decrypt(b []byte) {
	for i, c := range b {
		p := c ^ k.stream()
		k.update(p)
		b[i] = p
	}
}

func (k *zipKeys) encrypt(b []byte) {
	for i, p := range b {
		c := p ^ k.stream()
		k.update(p)
		b[i] = c
	}
}

// zipCryptoDecrypt decrypts a ZipCrypto entry: a 12-byte header whose last
// byte is check, then the data.
func zipCryptoDecrypt(raw, password []byte, check byte) ([]byte, error) {
	if len(raw) < 12 {
		return nil, errors.New("encrypted entry too short")
	}
	buf := append([]byte(nil), raw...)
	newZipKeys(password).decrypt(buf)
	if buf[11] != check {
		return nil, ErrZipPassword
	}
	return buf[12:], nil
}

// ZipCryptoEncrypt encrypts data for a ZipCrypto entry (for simulators and
// tests): header is 11 random bytes, check the CRC's top byte.
func ZipCryptoEncrypt(data, password, header []byte, check byte) []byte {
	out := make([]byte, 0, 12+len(data))
	out = append(out, header[:11]...)
	out = append(out, check)
	out = append(out, data...)
	newZipKeys(password).encrypt(out)
	return out
}

// winzipAES returns the key length and actual compression method from an
// entry's 0x9901 extra field.
func winzipAES(extra []byte) (keyLen int, method uint16, err error) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+n > len(extra) {
			break
		}
		if id == zipExtraAES && n >= 7 {
			body := extra[4 : 4+n]
			switch body[4] {
			case 1:
				keyLen = 16
			case 2:
				keyLen = 24
			case 3:
				keyLen = 32
			default:
				return 0, 0, fmt.Errorf("AES strength %d is unknown", body[4])
			}
			return keyLen, binary.LittleEndian.Uint16(body[5:]), nil
		}
		extra = extra[4+n:]
	}
	return 0, 0, errors.New("AES entry without its 0x9901 extra field")
}

func winzipKeys(password, salt []byte, keyLen int) (enc, auth, verify []byte, err error) {
	k, err := pbkdf2.Key(sha1.New, string(password), salt, 1000, 2*keyLen+2)
	if err != nil {
		return nil, nil, nil, err
	}
	return k[:keyLen], k[keyLen : 2*keyLen], k[2*keyLen:], nil
}

// winzipCTR is AES in counter mode with a little-endian counter starting
// at 1, as WinZip AES uses (crypto/cipher's CTR counts big-endian).
func winzipCTR(key, data []byte) error {
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var ctr, ks [16]byte
	for i := 0; i < len(data); i += 16 {
		for j := range ctr { // increment little-endian
			ctr[j]++
			if ctr[j] != 0 {
				break
			}
		}
		b.Encrypt(ks[:], ctr[:])
		for j := 0; j < 16 && i+j < len(data); j++ {
			data[i+j] ^= ks[j]
		}
	}
	return nil
}

func winzipAESDecrypt(f *zip.File, raw, password []byte) ([]byte, uint16, error) {
	keyLen, method, err := winzipAES(f.Extra)
	if err != nil {
		return nil, 0, err
	}
	saltLen := keyLen / 2
	if len(raw) < saltLen+2+zipAESAuthLen {
		return nil, 0, errors.New("AES entry too short")
	}
	salt, pv := raw[:saltLen], raw[saltLen:saltLen+2]
	body := raw[saltLen+2 : len(raw)-zipAESAuthLen]
	tag := raw[len(raw)-zipAESAuthLen:]
	enc, auth, verify, err := winzipKeys(password, salt, keyLen)
	if err != nil {
		return nil, 0, err
	}
	if subtle.ConstantTimeCompare(pv, verify) != 1 {
		return nil, 0, ErrZipPassword
	}
	m := hmac.New(sha1.New, auth)
	m.Write(body)
	if !hmac.Equal(m.Sum(nil)[:zipAESAuthLen], tag) {
		return nil, 0, fmt.Errorf("%s: authentication code mismatch: %w", f.Name, ErrZipPassword)
	}
	out := append([]byte(nil), body...)
	if err := winzipCTR(enc, out); err != nil {
		return nil, 0, err
	}
	return out, method, nil
}

// WinZipAESEncrypt builds an AES-256 (AE-2) entry body and its 0x9901
// extra field for data already compressed with method (for simulators and
// tests).
func WinZipAESEncrypt(data, password, salt []byte, method uint16) (body, extra []byte, err error) {
	enc, auth, verify, err := winzipKeys(password, salt[:16], 32)
	if err != nil {
		return nil, nil, err
	}
	ct := append([]byte(nil), data...)
	if err := winzipCTR(enc, ct); err != nil {
		return nil, nil, err
	}
	m := hmac.New(sha1.New, auth)
	m.Write(ct)
	body = append(append(append(append([]byte(nil), salt[:16]...), verify...), ct...), m.Sum(nil)[:zipAESAuthLen]...)
	extra = []byte{0x01, 0x99, 7, 0, 2, 0, 'A', 'E', 3, 0, 0}
	binary.LittleEndian.PutUint16(extra[9:], method)
	return body, extra, nil
}
