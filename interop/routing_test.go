// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// buildRoutePeer builds ./routepeer for Linux into a temporary directory.
func buildRoutePeer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "routepeer"), "./routepeer")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

// TestRoutingWithXknx runs this module's router and xknx 3.20.0 on one
// multicast group inside one container (multicast does not leave Docker
// Desktop's virtual machine) with the keyring SecureTest.knxkeys of xknx's
// test suite: plain routing and KNX IP Secure routing (backbone key,
// timer synchronisation, with this module as time keeper and, started
// second, as follower), all with KNX Data Secure for the keyring's
// secured groups. Each side receives the other's plain and Data Secure
// group writes, and xknx reads a value this module answers.
// Covers: SIG-IPE-6708
func TestRoutingWithXknx(t *testing.T) {
	needDocker(t, xknxImage, "xknx")
	dir := buildRoutePeer(t)
	for _, mode := range []string{"plain", "secure", "secure-late"} {
		t.Run(mode, func(t *testing.T) {
			out, err := exec.Command("docker", "run", "--rm", "-v", dir+":/peer:ro", "--entrypoint", "python3", xknxImage,
				"-u", "/routing.py", mode, "/samples/SecureTest.knxkeys", "test").CombinedOutput()
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("driver: %v", err)
			}
			has := func(prefix string) bool {
				return slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, prefix) })
			}
			for _, want := range []string{
				"PEER RX 5.0.1 1/1/7 GroupValueWrite 01",    // xknx → us, plain group
				"PEER RX 5.0.1 0/4/0 GroupValueWrite 0c1a",  // xknx → us, Data Secure (refused if plain)
				"TELEGRAM 4.0.9 1/1/8 GroupValueWrite 01",   // us → xknx, plain group
				"TELEGRAM 4.0.9 0/4/3 GroupValueWrite 0c33", // us → xknx, Data Secure
				"READ 1/2/3 0c33",                           // xknx reads, we answer
				"DONE",
			} {
				if !has(want) {
					t.Errorf("missing %q", want)
				}
			}
			if mode == "secure-late" && !has("PEER READY keeper=false") {
				t.Error("this module did not follow the time of xknx, the time keeper")
			}
			if mode == "secure" && !has("PEER READY keeper=true") {
				t.Error("this module did not become the time keeper of the empty backbone")
			}
		})
	}
}
