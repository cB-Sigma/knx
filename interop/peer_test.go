// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// knxdImage is the knxd peer's image, built from ./peer.
const knxdImage = "sigma-knx-interop:knxd-0.14.54.1"

// needDocker skips the test unless SIGMA_KNX_INTEROP=1 is set and Docker
// answers, and builds the image from dir when it is missing.
func needDocker(t *testing.T, image, dir string) {
	t.Helper()
	if os.Getenv("SIGMA_KNX_INTEROP") != "1" {
		t.Skip("set SIGMA_KNX_INTEROP=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	if exec.Command("docker", "image", "inspect", image).Run() == nil {
		return
	}
	out, err := exec.Command("docker", "build", "-q", "-t", image, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// knxd is knxd running in a container as a KNXnet/IP server.
type knxd struct {
	t    *testing.T
	name string
	addr string
}

func startKnxd(t *testing.T) *knxd {
	t.Helper()
	port := freeUDP(t)
	k := &knxd{t: t, name: fmt.Sprintf("sigma-knxd-%d", time.Now().UnixNano()), addr: fmt.Sprintf("127.0.0.1:%d", port)}
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", k.name, "-p", fmt.Sprintf("127.0.0.1:%d:3671/udp", port), knxdImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() || os.Getenv("SIGMA_KNX_INTEROP_LOG") == "1" {
			logs, _ := exec.Command("docker", "logs", k.name).CombinedOutput()
			t.Logf("knxd output:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", k.name).Run()
	})
	// knxd is ready once its local socket exists.
	deadline := time.Now().Add(20 * time.Second)
	for exec.Command("docker", "exec", k.name, "test", "-S", "/tmp/eib").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatal("knxd did not start")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return k
}

// tool runs knxtool against knxd's local socket and returns its output.
func (k *knxd) tool(args ...string) string {
	k.t.Helper()
	full := append([]string{"exec", k.name, "knxtool", args[0], "local:/tmp/eib"}, args[1:]...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil {
		k.t.Fatalf("knxtool %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// listener is knxtool groupsocketlisten: every group telegram on knxd's
// bus, one per line.
type listener struct {
	t     *testing.T
	cmd   *exec.Cmd
	mu    sync.Mutex
	lines []string
}

func (k *knxd) listen() *listener {
	k.t.Helper()
	l := &listener{t: k.t}
	l.cmd = exec.Command("docker", "exec", k.name, "stdbuf", "-oL", "knxtool", "groupsocketlisten", "local:/tmp/eib")
	r, w := io.Pipe()
	l.cmd.Stdout, l.cmd.Stderr = w, w
	if err := l.cmd.Start(); err != nil {
		k.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			l.mu.Lock()
			l.lines = append(l.lines, sc.Text())
			l.mu.Unlock()
		}
	}()
	k.t.Cleanup(func() { _ = l.cmd.Process.Kill(); _ = w.Close() })
	time.Sleep(500 * time.Millisecond)
	return l
}

// expect waits for a line containing every part.
func (l *listener) expect(within time.Duration, parts ...string) string {
	l.t.Helper()
	deadline := time.Now().Add(within)
	for {
		l.mu.Lock()
		for _, line := range l.lines {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(line, p)
			}
			if ok {
				l.mu.Unlock()
				return line
			}
		}
		all := strings.Join(l.lines, "\n")
		l.mu.Unlock()
		if time.Now().After(deadline) {
			l.t.Fatalf("knxtool saw no line with %q; it saw:\n%s", parts, all)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
