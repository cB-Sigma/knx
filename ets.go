package knx

import (
	"archive/zip"
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
)

// ETS project import. An ETS project export (.knxproj) is a zip: the
// project's own files sit in a folder named after the project id
// (P-xxxx/0.xml, P-xxxx/project.xml), next to a P-xxxx.signature entry and
// the knx_master.xml catalogue. A password-protected export replaces the
// folder with an inner P-xxxx.zip whose entries are encrypted (etszip.go).
// 0.xml holds the installation: group addresses (with name and datapoint
// type, inside nested group ranges) and the topology, whose devices' group
// objects link to group addresses and carry read/write flags. The layout
// facts come from the KNX XML project schema as published by KNX
// Association and as read for facts in xknxproject (GPL-2.0-only); no code was
// taken from it.

// ETSGroupAddress is one group address from a project.
type ETSGroupAddress struct {
	Address GroupAddress
	Name    string
	// DPT is the datapoint type (from the group address, else from a
	// linked group object); empty when the project has none.
	DPT string
	// Range is the innermost group range's name.
	Range string
	// Read and Write report whether any linked group object has the read
	// or write flag set; nil when no linked object states it.
	Read, Write *bool
}

// ETSProject is what the import takes from a project.
type ETSProject struct {
	Name           string
	GroupAddresses []ETSGroupAddress
}

// ErrProjectPassword is returned for a protected project without a password.
var ErrProjectPassword = errors.New("the ETS project is password-protected and no password was given")

// ParseETSProject reads a .knxproj export, or a bare 0.xml.
func ParseETSProject(data []byte, password string) (*ETSProject, error) {
	if !bytes.HasPrefix(data, []byte("PK")) {
		return parseProjectXML(data)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not an ETS project export: %w", err)
	}
	id := ""
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
		if strings.HasPrefix(f.Name, "P-") && strings.HasSuffix(f.Name, ".signature") {
			id = strings.TrimSuffix(f.Name, ".signature")
		}
	}
	if id == "" { // tolerate an export without its signature entry
		for name := range files {
			if strings.HasPrefix(name, "P-") && strings.HasSuffix(name, "/0.xml") {
				id = strings.TrimSuffix(name, "/0.xml")
			}
		}
	}
	if id == "" {
		return nil, errors.New("not an ETS project export: no P-… project in the archive")
	}
	if f := files[id+"/0.xml"]; f != nil {
		b, err := readZipEntry(f, nil)
		if err != nil {
			return nil, err
		}
		return parseProjectXML(b)
	}
	inner := files[id+".zip"]
	if inner == nil {
		return nil, fmt.Errorf("the archive has no %s/0.xml or %s.zip", id, id)
	}
	if password == "" {
		return nil, ErrProjectPassword
	}
	b, err := readZipEntry(inner, nil)
	if err != nil {
		return nil, err
	}
	iz, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("the protected project: %w", err)
	}
	for _, f := range iz.File {
		if f.Name != "0.xml" {
			continue
		}
		// ETS 6 (AES entries) derives the zip password from the project
		// password; ETS 4/5 (ZipCrypto) uses it as given.
		pw := []byte(password)
		if f.Method == zipMethodAES {
			pw = etsZipPassword(password)
		}
		x, err := readZipEntry(f, pw)
		if err != nil {
			return nil, err
		}
		return parseProjectXML(x)
	}
	return nil, errors.New("the protected project has no 0.xml")
}

// etsZipPassword is ETS 6's zip password for a project password:
// base64 of PBKDF2-HMAC-SHA256 over the UTF-16LE password, salt
// "21.project.ets.knx.org", 65536 iterations, 32 bytes.
func etsZipPassword(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	k, _ := pbkdf2.Key(sha256.New, string(b), []byte("21.project.ets.knx.org"), 65536, 32)
	return []byte(base64.StdEncoding.EncodeToString(k))
}

// ETSZipPassword exposes etsZipPassword for simulators.
func ETSZipPassword(password string) []byte { return etsZipPassword(password) }

func attr(se xml.StartElement, name string) (string, bool) {
	for _, a := range se.Attr {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value, true
		}
	}
	return "", false
}

func flag(v string, ok bool) *bool {
	if !ok {
		return nil
	}
	b := v == "Enabled" || v == "true" || v == "1"
	return &b
}

// gaRef reduces a group address id or reference to the part after the
// project prefix ("P-0123-0_GA-7" and "GA-7" both give "GA-7").
func gaRef(s string) string {
	if _, after, ok := strings.Cut(s, "_"); ok && strings.HasPrefix(s, "P-") {
		return after
	}
	return s
}

func firstDPT(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

type comObject struct {
	dpt         string
	read, write *bool
	links       []string
}

func parseProjectXML(data []byte) (*ETSProject, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	p := &ETSProject{}
	var ranges []string
	var stack []string
	byRef := map[string]int{}
	var objs []*comObject
	var cur *comObject
	sawProject := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("0.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			switch t.Name.Local {
			case "Project":
				sawProject = true
			case "Installation":
				if p.Name == "" {
					p.Name, _ = attr(t, "Name")
				}
			case "GroupRange":
				n, _ := attr(t, "Name")
				ranges = append(ranges, n)
			case "GroupAddress":
				a, _ := attr(t, "Address")
				n, err := strconv.ParseUint(a, 10, 16)
				if err != nil {
					continue
				}
				g := ETSGroupAddress{Address: GroupAddress(n)}
				g.Name, _ = attr(t, "Name")
				dpt, _ := attr(t, "DatapointType")
				g.DPT = firstDPT(dpt)
				if len(ranges) > 0 {
					g.Range = ranges[len(ranges)-1]
				}
				if id, ok := attr(t, "Id"); ok {
					byRef[gaRef(id)] = len(p.GroupAddresses)
				}
				p.GroupAddresses = append(p.GroupAddresses, g)
			case "ComObjectInstanceRef":
				cur = &comObject{}
				d, _ := attr(t, "DatapointType")
				cur.dpt = firstDPT(d)
				cur.read = flag(attr(t, "ReadFlag"))
				cur.write = flag(attr(t, "WriteFlag"))
				if l, ok := attr(t, "Links"); ok {
					cur.links = append(cur.links, strings.Fields(l)...)
				}
				objs = append(objs, cur)
			case "Send", "Receive":
				if cur != nil {
					if r, ok := attr(t, "GroupAddressRefId"); ok {
						cur.links = append(cur.links, r)
					}
				}
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			switch t.Name.Local {
			case "GroupRange":
				if len(ranges) > 0 {
					ranges = ranges[:len(ranges)-1]
				}
			case "ComObjectInstanceRef":
				cur = nil
			}
		}
	}
	if !sawProject && len(p.GroupAddresses) == 0 {
		return nil, errors.New("0.xml is not an ETS project (no Project element)")
	}
	yes := func(dst **bool, v *bool) {
		if v == nil {
			return
		}
		if *dst == nil || *v {
			b := *v
			*dst = &b
		}
	}
	for _, o := range objs {
		for _, l := range o.links {
			i, ok := byRef[gaRef(l)]
			if !ok {
				continue
			}
			g := &p.GroupAddresses[i]
			if g.DPT == "" {
				g.DPT = o.dpt
			}
			yes(&g.Read, o.read)
			yes(&g.Write, o.write)
		}
	}
	return p, nil
}

// slugName makes a point or device name from an ETS name.
func slugName(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// actuatorDPT reports whether a datapoint type is usually written by
// controllers (switching, dimming, setpoints, modes) rather than measured.
func actuatorDPT(d DPT) bool {
	switch d.Main {
	case 1, 2, 3, 5, 6, 17, 18, 20, 232:
		return true
	}
	return false
}

// ETSPoint is a group address from a project made ready for use as a
// point: a unique name, the device it belongs to and whether it is written
// or read on connect.
type ETSPoint struct {
	// Name is a lower-case slug of the group address name, unique among
	// the points (the address is appended on a clash, "ga-" plus the
	// address when the name is empty).
	Name string
	// GroupAddress is the three-level address, such as "1/2/3".
	GroupAddress string
	// DPT is the datapoint type in "main.sub" form, such as "9.001".
	DPT string
	// Device is a slug of the innermost group range's name, or the
	// fallback given to ETSPoints.
	Device string
	// Writable comes from the linked group objects' write flag, else from
	// the datapoint type (switching, dimming, setpoints and modes are
	// written; measurements are not).
	Writable bool
	// ReadOnStart is set when a linked group object has the read flag.
	ReadOnStart bool
	// Labels are "knx-ets".
	Labels []string
}

// ETSPoints turns a project's group addresses into points. Addresses that
// already carry a configured point, and addresses without a datapoint
// type, are left out (noDPT lists the latter). configured gives the names
// and group addresses already in use (only those two fields are read).
// Devices come from the innermost group range; fallback is the device for
// addresses outside any range.
func ETSPoints(p *ETSProject, configured []ETSPoint, fallback string) (pts []ETSPoint, noDPT []string) {
	names := map[string]bool{}
	gas := map[GroupAddress]bool{}
	for _, ps := range configured {
		names[ps.Name] = true
		if g, err := ParseGroupAddress(ps.GroupAddress); err == nil {
			gas[g] = true
		}
	}
	for _, g := range p.GroupAddresses {
		if gas[g.Address] {
			continue
		}
		gas[g.Address] = true
		if g.DPT == "" {
			noDPT = append(noDPT, g.Address.String())
			continue
		}
		dpt, err := ParseDPT(g.DPT)
		if err != nil && !errors.Is(err, ErrDPTRaw) {
			noDPT = append(noDPT, g.Address.String())
			continue
		}
		ga := strings.ReplaceAll(g.Address.String(), "/", "-")
		name := slugName(g.Name)
		if name == "" {
			name = "ga-" + ga
		}
		if names[name] {
			name += "-" + ga
		}
		names[name] = true
		dev := slugName(g.Range)
		if dev == "" {
			dev = fallback
		}
		ps := ETSPoint{Name: name, GroupAddress: g.Address.String(), DPT: dpt.String(), Device: dev,
			Labels: []string{"knx-ets"}}
		switch {
		case g.Write != nil:
			ps.Writable = *g.Write
		default:
			ps.Writable = actuatorDPT(dpt)
		}
		if g.Read != nil && *g.Read {
			ps.ReadOnStart = true
		}
		pts = append(pts, ps)
	}
	return pts, noDPT
}
