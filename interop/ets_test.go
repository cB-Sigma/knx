// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/json"
	"errors"
	"os/exec"
	"sort"
	"testing"

	"github.com/cB-Sigma/knx"
)

// xknxImage holds xknx 3.20.0 and xknxproject 3.10.0 with the sample ETS
// files of their test suites in /samples, built from ./xknx.
const xknxImage = "sigma-knx-xknx:3.20.0"

// sample returns a file of the image's /samples.
func sample(t *testing.T, name string) []byte {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--entrypoint", "cat", xknxImage, "/samples/"+name).Output()
	if err != nil {
		t.Fatalf("sample %s: %v", name, err)
	}
	return out
}

// peer runs peer.py in the image and decodes its JSON.
func peer(t *testing.T, v any, args ...string) {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"run", "--rm", xknxImage}, args...)...).Output()
	if err != nil {
		t.Fatalf("peer %v: %v\n%s", args, err, out)
	}
	if err := json.Unmarshal(out, v); err != nil {
		t.Fatalf("peer %v: %v\n%s", args, err, out)
	}
}

type xKeyring struct {
	Project    string `json:"project"`
	Interfaces []struct {
		Type     string `json:"type"`
		IA       string `json:"ia"`
		Host     string `json:"host"`
		UserID   int    `json:"user_id"`
		Password string `json:"password"`
		Auth     string `json:"auth"`
		HostAuth string `json:"host_auth"`
	} `json:"interfaces"`
	Devices []struct {
		IA   string `json:"ia"`
		Auth string `json:"auth"`
		Mgmt string `json:"mgmt"`
	} `json:"devices"`
	Backbone  bool `json:"backbone"`
	GroupKeys int  `json:"group_keys"`
}

// TestKeyringsAgainstXknx reads the keyrings ETS wrote for xknx's test
// suite with this module and with xknx, and compares every interface
// (type, address, host, user, decrypted password), every device
// (authentication code, management password), the backbone and the
// number of group keys; a wrong password is refused.
func TestKeyringsAgainstXknx(t *testing.T) {
	needDocker(t, xknxImage, "xknx")
	for _, tc := range []struct{ file, password string }{
		{"keyring.knxkeys", "pwd"},
		{"testcase.knxkeys", "password"},
		{"special_chars_secure_tunnel.knxkeys", "test"},
		{"DataSecure_only_one_interface.knxkeys", "test"},
		{"DataSecure_usb.knxkeys", "test"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var want xKeyring
			peer(t, &want, "keyring", "/samples/"+tc.file, tc.password)
			data := sample(t, tc.file)
			k, err := knx.ParseKeyring(data, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if k.Project != want.Project || k.Backbone != want.Backbone || k.GroupKeys != want.GroupKeys {
				t.Errorf("project %q backbone %v group keys %d; xknx %q %v %d", k.Project, k.Backbone, k.GroupKeys, want.Project, want.Backbone, want.GroupKeys)
			}
			if len(k.Interfaces) != len(want.Interfaces) {
				t.Fatalf("%d interfaces, xknx %d", len(k.Interfaces), len(want.Interfaces))
			}
			for i, in := range k.Interfaces {
				w := want.Interfaces[i]
				if in.Type != w.Type || in.IndividualAddress != w.IA || in.Host != w.Host || in.UserID != w.UserID || in.Password != w.Password || in.Authentication != w.Auth {
					t.Errorf("interface %d: %+v\nxknx: %+v", i, in, w)
				}
				// The secure tunnel's credentials, with the device
				// authentication code of its host.
				if in.UserID != 0 && in.Password != "" {
					got, auth, err := k.Tunnel(in.IndividualAddress, 0)
					wantAuth := w.HostAuth
					if wantAuth == "" {
						wantAuth = w.Auth
					}
					if err != nil || got.UserID != w.UserID || got.Password != w.Password || auth != wantAuth {
						t.Errorf("Tunnel(%s) = %d %q %q %v; xknx %d %q %q", in.IndividualAddress, got.UserID, got.Password, auth, err, w.UserID, w.Password, wantAuth)
					}
				}
			}
			if len(k.Devices) != len(want.Devices) {
				t.Fatalf("%d devices, xknx %d", len(k.Devices), len(want.Devices))
			}
			for i, d := range k.Devices {
				w := want.Devices[i]
				if d.IndividualAddress != w.IA || d.Authentication != w.Auth || d.ManagementPassword != w.Mgmt {
					t.Errorf("device %d: %+v\nxknx: %+v", i, d, w)
				}
			}
			if _, err := knx.ParseKeyring(data, tc.password+"x"); err == nil {
				t.Error("a wrong password was accepted")
			}
			t.Logf("%d interfaces, %d devices, backbone %v, %d group keys: same as xknx", len(k.Interfaces), len(k.Devices), k.Backbone, k.GroupKeys)
		})
	}
}

type xProject struct {
	Name           string `json:"name"`
	GroupAddresses []struct {
		Address string `json:"address"`
		Raw     int    `json:"raw"`
		Name    string `json:"name"`
		DPT     string `json:"dpt"`
	} `json:"group_addresses"`
}

// TestProjectsAgainstXknxproject reads the projects ETS 4, 5 and 6 wrote
// for xknxproject's test suite (plain and password-protected) with this
// module and with xknxproject, and compares the group addresses: the
// same set, the same names, and the same datapoint type wherever this
// module reports one.
func TestProjectsAgainstXknxproject(t *testing.T) {
	needDocker(t, xknxImage, "xknx")
	for _, tc := range []struct{ file, password string }{
		{"xknx_test_project.knxproj", "test"},
		{"xknx_test_project_no_password.knxproj", ""},
		{"test_project-ets4.knxproj", "test"},
		{"test_project-ets4-no_password.knxproj", ""},
		{"module-definition-test.knxproj", ""},
		{"testprojekt-ets6-functions.knxproj", ""},
		{"ets6_two_level.knxproj", ""},
		{"ets6_free.knxproj", ""},
		{"smart_linking.knxproj", "test"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			pw := tc.password
			if pw == "" {
				pw = "-"
			}
			var want xProject
			peer(t, &want, "project", "/samples/"+tc.file, pw)
			p, err := knx.ParseETSProject(sample(t, tc.file), tc.password)
			if err != nil {
				t.Fatal(err)
			}
			got := map[int]knx.ETSGroupAddress{}
			for _, g := range p.GroupAddresses {
				got[int(g.Address)] = g
			}
			if len(got) != len(want.GroupAddresses) {
				t.Errorf("%d group addresses, xknxproject %d", len(got), len(want.GroupAddresses))
			}
			var inferred []string
			for _, w := range want.GroupAddresses {
				g, ok := got[w.Raw]
				if !ok {
					t.Errorf("missing %s %q", w.Address, w.Name)
					continue
				}
				if g.Name != w.Name {
					t.Errorf("%s: name %q, xknxproject %q", w.Address, g.Name, w.Name)
				}
				switch {
				case g.DPT == "" && w.DPT != "":
					inferred = append(inferred, w.Address)
				case g.DPT != "":
					d, err := knx.ParseDPT(g.DPT)
					if err != nil && !errors.Is(err, knx.ErrDPTRaw) {
						t.Errorf("%s: DPT %q: %v", w.Address, g.DPT, err)
						break
					}
					wd, _ := knx.ParseDPT(w.DPT)
					if d.Main != wd.Main || (wd.Sub != 0 && d.Sub != wd.Sub) {
						t.Errorf("%s: DPT %s, xknxproject %s", w.Address, d, w.DPT)
					}
				}
			}
			sort.Strings(inferred)
			t.Logf("%d group addresses match xknxproject; %d without a DPT here that xknxproject has: %v", len(want.GroupAddresses), len(inferred), inferred)
		})
	}
}
