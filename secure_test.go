package knx_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/knx"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The vectors are the KNX IP Secure example frames as published (recomputed)
// in the MIT-licensed xknx project, examples/ip_secure_calculations.py.
//
// Covers: SIG-IPE-847
func TestKNXSecureVectors(t *testing.T) {
	// Password derivations (PBKDF2-HMAC-SHA256, 65536 iterations, 16 bytes).
	if got, want := knx.DeviceAuthCode("trustme"), hx(t, "e1 58 e4 01 20 47 bd 6c c4 1a af bc 5c 04 c1 fc"); !bytes.Equal(got, want) {
		t.Errorf("device authentication code = %x, want %x", got, want)
	}
	pw := knx.UserPasswordHash("secret")
	if want := hx(t, "03 fc ed b6 66 60 25 1e c8 1a 1a 71 69 01 69 6a"); !bytes.Equal(pw, want) {
		t.Errorf("user password hash = %x, want %x", pw, want)
	}

	// SESSION_RESPONSE MAC with the device authentication code.
	priv, err := ecdh.X25519().NewPrivateKey(hx(t, "b8 fa bd 62 66 5d 8b 9e 8a 9d 8b 1f 4b ca 42 c8 c2 78 9a 61 10 f5 0e 9d d7 85 b3 ed e8 83 f3 78"))
	if err != nil {
		t.Fatal(err)
	}
	clientPub := priv.PublicKey().Bytes()
	serverPub := hx(t, "bd f0 99 90 99 23 14 3e f0 a5 de 0b 3b e3 68 7b c5 bd 3c f5 f9 e6 f9 01 69 9c d8 70 ec 1f f8 24")
	mac := knx.SessionResponseMAC(knx.DeviceAuthCode("trustme"), 1, clientPub, serverPub)
	if want := hx(t, "a9 22 50 5a aa 43 61 63 57 0b d5 49 4c 2d f2 a3"); !bytes.Equal(mac, want) {
		t.Errorf("SESSION_RESPONSE MAC = %x, want %x", mac, want)
	}

	// SESSION_AUTHENTICATE for user 1 with password "secret".
	auth := knx.SessionAuthenticateFrame(1, knx.SessionAuthenticateMAC(pw, 1, clientPub, serverPub)).Encode()
	if want := hx(t, "06 10 09 53 00 18 00 01 1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de"); !bytes.Equal(auth, want) {
		t.Errorf("SESSION_AUTHENTICATE = %x, want %x", auth, want)
	}

	// SECURE_WRAPPER around it, with the session key from X25519.
	key, err := knx.SharedSessionKey(priv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	inner, _ := knx.ParseFrame(auth)
	w := knx.SecureWrapper{SessionID: 1, Seq: 0, Serial: [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78}, Tag: [2]byte{0xaf, 0xfe}}
	wrapped := w.Wrap(key, inner).Encode()
	want := hx(t, "06 10 09 50 00 3e 00 01 00 00 00 00 00 00 00 fa 12 34 56 78 af fe"+
		"79 15 a4 f3 6e 6e 42 08 d2 8b 4a 20 7d 8f 35 c0 d1 38 c2 6a 7b 5e 71 69"+
		"52 db a8 e7 e4 bd 80 bd 7d 86 8a 3a e7 87 49 de")
	if !bytes.Equal(wrapped, want) {
		t.Errorf("wrapped SESSION_AUTHENTICATE =\n%x, want\n%x", wrapped, want)
	}
	// And back.
	fr, _ := knx.ParseFrame(want)
	gw, got, err := knx.ParseSecureWrapper(key, fr.Body)
	if err != nil || got.Service != knx.SvcSessionAuthenticate || !bytes.Equal(got.Encode(), auth) || gw != w {
		t.Errorf("unwrap = %+v %+v %v", gw, got, err)
	}

	// SESSION_STATUS (authenticated) from the server.
	st := hx(t, "06 10 09 50 00 2e 00 01 00 00 00 00 00 00 00 fa aa aa aa aa af fe"+
		"26 15 6d b5 c7 49 88 8f a3 73 c3 e0 b4 bd e4 49 7c 39 5e 4b 1c 2f 46 a1")
	fr, _ = knx.ParseFrame(st)
	_, got, err = knx.ParseSecureWrapper(key, fr.Body)
	if err != nil || !bytes.Equal(got.Encode(), knx.SessionStatusFrame(knx.SessionAuthSuccess).Encode()) {
		t.Errorf("SESSION_STATUS unwrap = %x %v", got.Encode(), err)
	}
	// Any flipped bit fails the MAC.
	for _, i := range []int{7, 9, 25, len(st) - 1} {
		bad := append([]byte(nil), st...)
		bad[i] ^= 0x01
		fr, _ := knx.ParseFrame(bad)
		if _, _, err := knx.ParseSecureWrapper(key, fr.Body); !errors.Is(err, knx.ErrSecure) {
			t.Errorf("bit %d flipped: %v, want ErrSecure", i, err)
		}
	}
	// A wrong key fails too.
	if _, _, err := knx.ParseSecureWrapper(pw, fr.Body); !errors.Is(err, knx.ErrSecure) {
		t.Errorf("wrong key: %v", err)
	}
}
