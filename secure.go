package knx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// KNX IP Secure (KNX Standard volume 3 part 8 chapter 9, "KNXnet/IP
// Secure"; ISO 22510:2019 annex). The specification itself is available to
// KNX members only; this implementation follows publicly documented facts:
// the frame layouts and example frames as reproduced in the MIT-licensed
// xknx project (xknx/secure/security_primitives.py,
// examples/ip_secure_calculations.py), whose example values our tests use
// as vectors.
//
// A secure session runs over a KNXnet/IP TCP connection:
//
//	client → SESSION_REQUEST       HPAI (TCP, route back) + client X25519 public key
//	server → SESSION_RESPONSE      session id + server public key + MAC
//	                               (keyed with the device authentication code)
//	client → SESSION_AUTHENTICATE  wrapped; user id + MAC keyed with the
//	                               user password hash
//	server → SESSION_STATUS        wrapped; 0 = authenticated
//
// Everything after SESSION_RESPONSE travels in SECURE_WRAPPER frames,
// encrypted and authenticated with the session key, the first 16 bytes of
// SHA-256 over the X25519 shared secret. The wrapper uses AES-128 in a CCM
// construction: a CBC-MAC over block 0 (sequence, serial, tag, payload
// length), the 2-byte length of the associated data, the associated data
// (wrapper header and session id) and the plain frame, zero-padded; then
// CTR encryption where counter 0 (sequence, serial, tag, 0xFF, 0x00)
// encrypts the MAC and the following counters the frame.

// Security service types.
const (
	SvcSecureWrapper       uint16 = 0x0950
	SvcSessionRequest      uint16 = 0x0951
	SvcSessionResponse     uint16 = 0x0952
	SvcSessionAuthenticate uint16 = 0x0953
	SvcSessionStatus       uint16 = 0x0954
	FamilySecurity         byte   = 0x09
)

// Session status codes (SESSION_STATUS).
const (
	SessionAuthSuccess     byte = 0x00
	SessionAuthFailed      byte = 0x01
	SessionUnauthenticated byte = 0x02
	SessionTimeout         byte = 0x03
	SessionKeepalive       byte = 0x04
	SessionClose           byte = 0x05
)

const (
	macLen            = 16
	keyLen            = 32
	wrapperOverhead   = headerLen + 2 + 6 + 6 + 2 + macLen // 38
	sessionRespLen    = 2 + keyLen + macLen
	sessionAuthLen    = 2 + macLen
	userPasswordSalt  = "user-password.1.secure.ip.knx.org"
	deviceAuthSalt    = "device-authentication-code.1.secure.ip.knx.org"
	passwordIterCount = 65536
)

// MessageTagTunnelling is the message tag of unicast (session) wrappers.
var MessageTagTunnelling = [2]byte{0, 0}

// counter0Handshake is counter 0 of the SESSION_RESPONSE and
// SESSION_AUTHENTICATE MACs.
var counter0Handshake = [16]byte{14: 0xFF}

// ErrSecure marks a secure frame that failed verification.
var ErrSecure = errors.New("knx ip secure: verification failed")

func deriveKey(password, salt string) []byte {
	// ISO 8859-1 bytes of the password.
	b := make([]byte, 0, len(password))
	for _, r := range password {
		if r > 0xFF {
			r = '?'
		}
		b = append(b, byte(r))
	}
	k, err := pbkdf2.Key(sha256.New, string(b), []byte(salt), passwordIterCount, 16)
	if err != nil {
		panic(err) // only for invalid parameters, which are constant here
	}
	return k
}

// UserPasswordHash derives the 16-byte key of a tunnelling user's password
// (PBKDF2-HMAC-SHA256, 65536 iterations).
func UserPasswordHash(password string) []byte { return deriveKey(password, userPasswordSalt) }

// DeviceAuthCode derives the 16-byte device authentication code from its
// password (PBKDF2-HMAC-SHA256, 65536 iterations).
func DeviceAuthCode(password string) []byte { return deriveKey(password, deviceAuthSalt) }

// SessionKey derives the session key from the X25519 shared secret.
func SessionKey(shared []byte) []byte {
	h := sha256.Sum256(shared)
	return append([]byte(nil), h[:16]...)
}

// cbcMAC is the CBC-MAC of block0 ‖ len(adata) ‖ adata ‖ payload, zero-padded
// to whole blocks, with a zero IV.
func cbcMAC(block cipher.Block, b0 []byte, adata, payload []byte) []byte {
	in := make([]byte, 0, 16+2+len(adata)+len(payload)+15)
	in = append(in, b0...)
	in = binary.BigEndian.AppendUint16(in, uint16(len(adata)))
	in = append(in, adata...)
	in = append(in, payload...)
	if r := len(in) % 16; r != 0 {
		in = append(in, make([]byte, 16-r)...)
	}
	y := make([]byte, 16)
	for i := 0; i < len(in); i += 16 {
		subtle.XORBytes(y, y, in[i:i+16])
		block.Encrypt(y, y)
	}
	return y
}

// ctrXOR encrypts (or decrypts) mac with counter 0 and data with the
// following counters (the whole 16-byte block counts up, big-endian).
func ctrXOR(block cipher.Block, ctr0 []byte, mac, data []byte) (outMAC, outData []byte) {
	s := cipher.NewCTR(block, ctr0)
	outMAC = make([]byte, len(mac))
	s.XORKeyStream(outMAC, mac)
	outData = make([]byte, len(data))
	s.XORKeyStream(outData, data)
	return outMAC, outData
}

func newBlock(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("knx ip secure: key of %d bytes", len(key)))
	}
	return b
}

func xorKeys(a, b []byte) []byte {
	out := make([]byte, keyLen)
	subtle.XORBytes(out, a, b)
	return out
}

func handshakeMAC(key, adata []byte) []byte {
	blk := newBlock(key)
	mac := cbcMAC(blk, make([]byte, 16), adata, nil)
	enc, _ := ctrXOR(blk, counter0Handshake[:], mac, nil)
	return enc
}

func header(svc uint16, total int) []byte {
	b := []byte{headerLen, protocolVersion, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], svc)
	binary.BigEndian.PutUint16(b[4:], uint16(total))
	return b
}

// SessionResponseMAC is the MAC a server puts in SESSION_RESPONSE: keyed
// with the device authentication code, over the response header, the
// session id and the XOR of both public keys.
func SessionResponseMAC(deviceAuth []byte, sessionID uint16, clientPub, serverPub []byte) []byte {
	ad := header(SvcSessionResponse, headerLen+sessionRespLen)
	ad = binary.BigEndian.AppendUint16(ad, sessionID)
	ad = append(ad, xorKeys(clientPub, serverPub)...)
	return handshakeMAC(deviceAuth, ad)
}

// SessionAuthenticateMAC is the MAC of SESSION_AUTHENTICATE: keyed with the
// user password hash, over the authenticate header, the reserved byte, the
// user id and the XOR of both public keys.
func SessionAuthenticateMAC(passwordHash []byte, userID byte, clientPub, serverPub []byte) []byte {
	ad := header(SvcSessionAuthenticate, headerLen+sessionAuthLen)
	ad = append(ad, 0, userID)
	ad = append(ad, xorKeys(clientPub, serverPub)...)
	return handshakeMAC(passwordHash, ad)
}

// SessionRequestFrame builds SESSION_REQUEST (TCP route-back HPAI and the
// client's public key).
func SessionRequestFrame(clientPub []byte) Frame {
	return Frame{Service: SvcSessionRequest, Body: append(TCPHPAI().append(nil), clientPub...)}
}

// ParseSessionRequest returns the client's public key.
func ParseSessionRequest(b []byte) ([]byte, error) {
	_, rest, err := parseHPAI(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != keyLen {
		return nil, errors.New("knx ip secure: SESSION_REQUEST key is not 32 bytes")
	}
	return rest, nil
}

// SessionResponse is the server's answer to SESSION_REQUEST.
type SessionResponse struct {
	SessionID uint16
	ServerPub []byte
	MAC       []byte
}

// Frame is the SESSION_RESPONSE frame.
func (r SessionResponse) Frame() Frame {
	b := binary.BigEndian.AppendUint16(nil, r.SessionID)
	b = append(b, r.ServerPub...)
	return Frame{Service: SvcSessionResponse, Body: append(b, r.MAC...)}
}

// ParseSessionResponse reads a SESSION_RESPONSE body.
func ParseSessionResponse(b []byte) (SessionResponse, error) {
	if len(b) != sessionRespLen {
		return SessionResponse{}, errors.New("knx ip secure: SESSION_RESPONSE of the wrong length")
	}
	return SessionResponse{SessionID: binary.BigEndian.Uint16(b), ServerPub: b[2 : 2+keyLen], MAC: b[2+keyLen:]}, nil
}

// SessionAuthenticateFrame builds SESSION_AUTHENTICATE.
func SessionAuthenticateFrame(userID byte, mac []byte) Frame {
	return Frame{Service: SvcSessionAuthenticate, Body: append([]byte{0, userID}, mac...)}
}

// ParseSessionAuthenticate returns the user id and MAC.
func ParseSessionAuthenticate(b []byte) (byte, []byte, error) {
	if len(b) != sessionAuthLen {
		return 0, nil, errors.New("knx ip secure: SESSION_AUTHENTICATE of the wrong length")
	}
	return b[1], b[2:], nil
}

// SessionStatusFrame builds SESSION_STATUS.
func SessionStatusFrame(status byte) Frame {
	return Frame{Service: SvcSessionStatus, Body: []byte{status, 0}}
}

// SecureWrapper is the clear part of a SECURE_WRAPPER.
type SecureWrapper struct {
	SessionID uint16
	Seq       uint64 // 48 bits
	Serial    [6]byte
	Tag       [2]byte
}

func (w SecureWrapper) nonce() []byte {
	b := make([]byte, 0, 16)
	b = append(b, byte(w.Seq>>40), byte(w.Seq>>32), byte(w.Seq>>24), byte(w.Seq>>16), byte(w.Seq>>8), byte(w.Seq))
	b = append(b, w.Serial[:]...)
	return append(b, w.Tag[:]...)
}

// Wrap encrypts and authenticates a complete KNXnet/IP frame.
func (w SecureWrapper) Wrap(key []byte, inner Frame) Frame {
	plain := inner.Encode()
	total := wrapperOverhead + len(plain)
	ad := binary.BigEndian.AppendUint16(header(SvcSecureWrapper, total), w.SessionID)
	n := w.nonce()
	blk := newBlock(key)
	mac := cbcMAC(blk, binary.BigEndian.AppendUint16(append([]byte(nil), n...), uint16(len(plain))), ad, plain)
	encMAC, enc := ctrXOR(blk, append(n, 0xFF, 0x00), mac, plain)
	body := append([]byte(nil), ad[headerLen:]...)
	body = append(body, n...)
	body = append(body, enc...)
	return Frame{Service: SvcSecureWrapper, Body: append(body, encMAC...)}
}

// ParseSecureWrapper splits a SECURE_WRAPPER body, decrypts it with key and
// checks its MAC. It returns the clear fields and the inner frame. Wrappers
// may not be nested.
func ParseSecureWrapper(key []byte, body []byte) (SecureWrapper, Frame, error) {
	var w SecureWrapper
	if len(body) < wrapperOverhead-headerLen+headerLen {
		return w, Frame{}, fmt.Errorf("%w: SECURE_WRAPPER too short", ErrSecure)
	}
	w.SessionID = binary.BigEndian.Uint16(body)
	s := body[2:8]
	w.Seq = uint64(s[0])<<40 | uint64(s[1])<<32 | uint64(s[2])<<24 | uint64(s[3])<<16 | uint64(s[4])<<8 | uint64(s[5])
	copy(w.Serial[:], body[8:14])
	copy(w.Tag[:], body[14:16])
	enc := body[16 : len(body)-macLen]
	encMAC := body[len(body)-macLen:]
	n := w.nonce()
	blk := newBlock(key)
	mac, plain := ctrXOR(blk, append(append([]byte(nil), n...), 0xFF, 0x00), encMAC, enc)
	ad := binary.BigEndian.AppendUint16(header(SvcSecureWrapper, headerLen+len(body)), w.SessionID)
	want := cbcMAC(blk, binary.BigEndian.AppendUint16(n, uint16(len(plain))), ad, plain)
	if subtle.ConstantTimeCompare(mac, want) != 1 {
		return w, Frame{}, fmt.Errorf("%w: SECURE_WRAPPER MAC mismatch", ErrSecure)
	}
	inner, err := ParseFrame(plain)
	if err != nil {
		return w, Frame{}, fmt.Errorf("%w: %v", ErrSecure, err)
	}
	if inner.Service == SvcSecureWrapper || inner.Service == SvcSessionRequest || inner.Service == SvcSessionResponse {
		return w, Frame{}, fmt.Errorf("%w: service %#04x may not be wrapped", ErrSecure, inner.Service)
	}
	inner.Body = append([]byte(nil), inner.Body...)
	return w, inner, nil
}

// CheckMAC compares two MACs in constant time.
func CheckMAC(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// NewSessionKeyPair makes an X25519 key pair for one session.
func NewSessionKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// SharedSessionKey runs X25519 with the peer's public key and derives the
// session key.
func SharedSessionKey(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("knx ip secure: peer public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("knx ip secure: key agreement: %w", err)
	}
	return SessionKey(shared), nil
}
