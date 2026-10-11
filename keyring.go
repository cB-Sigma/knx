package knx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// ETS keyring export (.knxkeys). An XML document whose Keyring root
// carries Project, Created and Signature attributes; Interface elements
// (Type Tunneling, USB, …) with IndividualAddress, Host, UserID and an
// encrypted Password; Devices/Device elements with IndividualAddress and
// encrypted Authentication (device authentication code) and
// ManagementPassword; optional Backbone (secure routing) and GroupAddresses
// (KNX Data Secure keys).
//
// Encrypted attributes are base64 of AES-128-CBC with the key
// PBKDF2-HMAC-SHA256(keyring password, "1.keyring.ets.knx.org", 65536
// rounds, 16 bytes) and the IV the first 16 bytes of SHA-256 over the
// Created attribute; a decrypted password is preceded by 8 filler bytes
// and followed by padding whose every byte is its length. The Signature is
// the first 16 bytes of SHA-256 over a serialisation of the document
// (keyringDigest) ending with the base64 password key, so a wrong password
// is detected before anything is decrypted. These facts are as publicly
// documented by the MIT-licensed xknx project (xknx/secure/keyring.py); no
// code was taken from it.

// ErrKeyringPassword is returned when the keyring signature does not match
// the password.
var ErrKeyringPassword = errors.New("the keyring password does not match the keyring")

// KeyringInterface is one interface (tunnel, USB) from a keyring.
type KeyringInterface struct {
	Type              string
	IndividualAddress string
	Host              string
	UserID            int
	Password          string
	Authentication    string
}

// KeyringDevice is one secure device from a keyring.
type KeyringDevice struct {
	IndividualAddress  string
	Authentication     string
	ManagementPassword string
}

// Keyring is a decrypted keyring.
type Keyring struct {
	Project    string
	Interfaces []KeyringInterface
	Devices    []KeyringDevice
	// Backbone reports a secure routing backbone key; GroupKeys counts
	// KNX Data Secure group keys. This package reports both and uses
	// neither.
	Backbone  bool
	GroupKeys int
}

func keyringKey(password string) []byte {
	k, _ := pbkdf2.Key(sha256.New, password, []byte("1.keyring.ets.knx.org"), 65536, 16)
	return k
}

// keyringDigest serialises the document for the signature: per element
// 0x01, its name and its attributes sorted by name (except xmlns and
// Signature), each string preceded by its one-byte length; 0x02 at every
// element end; then the base64 password key.
func keyringDigest(data []byte, key []byte) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var out []byte
	str := func(s string) error {
		if len(s) > 255 {
			return errors.New("keyring attribute longer than 255 bytes")
		}
		out = append(out, byte(len(s)))
		out = append(out, s...)
		return nil
	}
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			out = append(out, 1)
			if err := str(qname(t.Name)); err != nil {
				return nil, err
			}
			attrs := make([][2]string, 0, len(t.Attr))
			for _, a := range t.Attr {
				n := qname(a.Name)
				if n == "xmlns" || n == "Signature" {
					continue
				}
				attrs = append(attrs, [2]string{n, a.Value})
			}
			sort.Slice(attrs, func(i, j int) bool { return attrs[i][0] < attrs[j][0] })
			for _, a := range attrs {
				if err := str(a[0]); err != nil {
					return nil, err
				}
				if err := str(a[1]); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			out = append(out, 2)
		}
	}
	if err := str(base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(out)
	return sum[:16], nil
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

type keyringCrypt struct {
	block cipher.Block
	iv    []byte
}

func (c *keyringCrypt) password(b64 string) (string, error) {
	if b64 == "" {
		return "", nil
	}
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(ct) == 0 || len(ct)%16 != 0 {
		return "", errors.New("encrypted value is not whole AES blocks")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > len(pt)-8 {
		return "", errors.New("encrypted value has bad padding")
	}
	return string(pt[8 : len(pt)-pad]), nil
}

// SealKeyringPassword encrypts a password as a keyring attribute (for
// simulators and tests); filler is the 8 leading bytes.
func SealKeyringPassword(keyringPassword, created, value string, filler [8]byte) string {
	b, _ := aes.NewCipher(keyringKey(keyringPassword))
	iv := sha256.Sum256([]byte(created))
	pt := append(filler[:], value...)
	pad := 16 - len(pt)%16
	for range pad {
		pt = append(pt, byte(pad))
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(b, iv[:16]).CryptBlocks(ct, pt)
	return base64.StdEncoding.EncodeToString(ct)
}

// SignKeyring returns the Signature attribute value for a keyring document
// (the Signature attribute's current value is ignored).
func SignKeyring(data []byte, keyringPassword string) (string, error) {
	d, err := keyringDigest(data, keyringKey(keyringPassword))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(d), nil
}

// ParseKeyring checks a keyring's signature and decrypts its passwords.
func ParseKeyring(data []byte, password string) (*Keyring, error) {
	if password == "" {
		return nil, errors.New("the keyring needs the password it was exported with")
	}
	var doc struct {
		XMLName    xml.Name `xml:"Keyring"`
		Project    string   `xml:"Project,attr"`
		Created    string   `xml:"Created,attr"`
		Signature  string   `xml:"Signature,attr"`
		Interfaces []struct {
			Type              string `xml:"Type,attr"`
			IndividualAddress string `xml:"IndividualAddress,attr"`
			Host              string `xml:"Host,attr"`
			UserID            string `xml:"UserID,attr"`
			Password          string `xml:"Password,attr"`
			Authentication    string `xml:"Authentication,attr"`
		} `xml:"Interface"`
		Backbone *struct{}  `xml:"Backbone"`
		Groups   []struct{} `xml:"GroupAddresses>Group"`
		Devices  []struct {
			IndividualAddress  string `xml:"IndividualAddress,attr"`
			Authentication     string `xml:"Authentication,attr"`
			ManagementPassword string `xml:"ManagementPassword,attr"`
		} `xml:"Devices>Device"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not an ETS keyring: %w", err)
	}
	key := keyringKey(password)
	if doc.Signature != "" {
		want, err := base64.StdEncoding.DecodeString(doc.Signature)
		if err != nil {
			return nil, fmt.Errorf("keyring signature: %w", err)
		}
		got, err := keyringDigest(data, key)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return nil, ErrKeyringPassword
		}
	}
	block, _ := aes.NewCipher(key)
	iv := sha256.Sum256([]byte(doc.Created))
	c := &keyringCrypt{block: block, iv: iv[:16]}
	k := &Keyring{Project: doc.Project, Backbone: doc.Backbone != nil, GroupKeys: len(doc.Groups)}
	for _, in := range doc.Interfaces {
		ki := KeyringInterface{Type: in.Type, IndividualAddress: in.IndividualAddress, Host: in.Host}
		if in.UserID != "" {
			ki.UserID, _ = strconv.Atoi(in.UserID)
		}
		var err error
		if ki.Password, err = c.password(in.Password); err != nil {
			return nil, fmt.Errorf("interface %s password: %w", in.IndividualAddress, err)
		}
		if ki.Authentication, err = c.password(in.Authentication); err != nil {
			return nil, fmt.Errorf("interface %s authentication: %w", in.IndividualAddress, err)
		}
		k.Interfaces = append(k.Interfaces, ki)
	}
	for _, d := range doc.Devices {
		kd := KeyringDevice{IndividualAddress: d.IndividualAddress}
		var err error
		if kd.Authentication, err = c.password(d.Authentication); err != nil {
			return nil, fmt.Errorf("device %s authentication: %w", d.IndividualAddress, err)
		}
		if kd.ManagementPassword, err = c.password(d.ManagementPassword); err != nil {
			return nil, fmt.Errorf("device %s management password: %w", d.IndividualAddress, err)
		}
		k.Devices = append(k.Devices, kd)
	}
	return k, nil
}

// Tunnel picks the secure tunnelling interface: the one at address when
// given, else the one for userID when non-zero, else the first tunnelling
// interface with a user. It returns that interface's user id, password and
// the device authentication code of its host (or of the interface).
func (k *Keyring) Tunnel(address string, userID int) (KeyringInterface, string, error) {
	var pick *KeyringInterface
	for i := range k.Interfaces {
		in := &k.Interfaces[i]
		if in.Type != "" && in.Type != "Tunneling" && in.Type != "Tunnelling" {
			continue
		}
		if in.UserID == 0 || in.Password == "" {
			continue
		}
		switch {
		case address != "":
			if in.IndividualAddress == address {
				pick = in
			}
		case userID != 0:
			if in.UserID == userID {
				pick = in
			}
		case pick == nil:
			pick = in
		}
		if pick != nil && (address != "" || userID != 0) {
			break
		}
	}
	if pick == nil {
		switch {
		case address != "":
			return KeyringInterface{}, "", fmt.Errorf("the keyring has no secure tunnel at %s", address)
		case userID != 0:
			return KeyringInterface{}, "", fmt.Errorf("the keyring has no secure tunnel for user %d", userID)
		}
		return KeyringInterface{}, "", errors.New("the keyring has no secure tunnelling interface")
	}
	auth := pick.Authentication
	for _, d := range k.Devices {
		if pick.Host != "" && d.IndividualAddress == pick.Host && d.Authentication != "" {
			auth = d.Authentication
		}
	}
	return *pick, auth, nil
}
