// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module against independent KNX
// implementations: knxd 0.14.54.1 (GPL-2.0, a test peer in a container
// built from ./peer) as a KNXnet/IP tunnelling server, and xknx and
// xknxproject (in a container built from ./xknx) reading ETS keyrings
// and projects. The tests are skipped unless SIGMA_KNX_INTEROP=1 is set
// and Docker is running.
package interop

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/knx"
)

// frames collects the L_Data frames a tunnel receives.
type frames struct {
	mu  sync.Mutex
	got []knx.LData
}

func (f *frames) add(l knx.LData) { f.mu.Lock(); f.got = append(f.got, l); f.mu.Unlock() }

// wait returns the first indication for ga with the service apci.
func (f *frames) wait(t *testing.T, within time.Duration, ga knx.GroupAddress, apci uint16) knx.LData {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		f.mu.Lock()
		for _, l := range f.got {
			if l.Code == knx.LDataInd && l.Group() == ga && l.APCI == apci {
				f.mu.Unlock()
				return l
			}
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("no indication %#x for %s within %s", apci, ga, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func dialKnxd(t *testing.T, k *knxd, f *frames) *knx.Tunnel {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tn, err := knx.DialTunnel(ctx, k.addr, knx.TunnelOptions{NAT: true, OnFrame: f.add,
		OnError: func(err error) { t.Logf("tunnel: %v", err) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tn.Close)
	return tn
}

func ga(t *testing.T, s string) knx.GroupAddress {
	t.Helper()
	g, err := knx.ParseGroupAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestTunnelThroughKnxd: two tunnels of this module to knxd (NAT mode, as
// through a container's port mapping). Group writes, reads and responses
// sent on one reach the other and knxtool on knxd's bus, and telegrams
// knxtool sends reach both tunnels; knxd confirms each request.
func TestTunnelThroughKnxd(t *testing.T) {
	needDocker(t, knxdImage, "peer")
	k := startKnxd(t)
	bus := k.listen()
	var fa, fb frames
	a := dialKnxd(t, k, &fa)
	b := dialKnxd(t, k, &fb)
	t.Logf("tunnels %s (channel %d) and %s (channel %d); gateway %+v", a.Address, a.Channel, b.Address, b.Channel, a.Gateway)
	if a.Address == b.Address {
		t.Errorf("both tunnels got %s", a.Address)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("description", func(t *testing.T) {
		if a.Gateway == nil {
			t.Fatal("knxd did not answer the description request")
		}
		if !a.Gateway.Supports(knx.FamilyTunnelling) {
			t.Errorf("families %+v", a.Gateway.Families)
		}
	})

	// Search is not run here: knxd sends its SEARCH_RESPONSE to the
	// endpoint in the request, and through the container's port mapping
	// that endpoint (the host's loopback) is not reachable from knxd.

	light := ga(t, "1/1/7")
	t.Run("group write", func(t *testing.T) {
		if err := a.Send(ctx, knx.GroupFrame(knx.LDataReq, light, knx.GroupValueWrite, []byte{1}, true)); err != nil {
			t.Fatal(err)
		}
		if v := fb.wait(t, 5*time.Second, light, knx.GroupValueWrite).Value(); len(v) != 1 || v[0] != 1 {
			t.Errorf("tunnel b got %x", v)
		}
		bus.expect(5*time.Second, "Write", "1/1/7", "01")
		dim := ga(t, "1/1/8")
		if err := a.Send(ctx, knx.GroupFrame(knx.LDataReq, dim, knx.GroupValueWrite, []byte{0x80}, false)); err != nil {
			t.Fatal(err)
		}
		bus.expect(5*time.Second, "Write", "1/1/8", "80")
		if v := fb.wait(t, 5*time.Second, dim, knx.GroupValueWrite).Value(); len(v) != 1 || v[0] != 0x80 {
			t.Errorf("tunnel b got %x", v)
		}
	})

	temp := ga(t, "1/2/3")
	t.Run("group read and response", func(t *testing.T) {
		if err := a.Send(ctx, knx.GroupFrame(knx.LDataReq, temp, knx.GroupValueRead, nil, true)); err != nil {
			t.Fatal(err)
		}
		fb.wait(t, 5*time.Second, temp, knx.GroupValueRead)
		bus.expect(5*time.Second, "Read", "1/2/3")
		if err := b.Send(ctx, knx.GroupFrame(knx.LDataReq, temp, knx.GroupValueResponse, []byte{0x0C, 0x1A}, false)); err != nil {
			t.Fatal(err)
		}
		if v := fa.wait(t, 5*time.Second, temp, knx.GroupValueResponse).Value(); len(v) != 2 || v[0] != 0x0C || v[1] != 0x1A {
			t.Errorf("tunnel a got response %x", v)
		}
		bus.expect(5*time.Second, "Response", "1/2/3", "0C 1A")
	})

	t.Run("telegrams from knxtool", func(t *testing.T) {
		k.tool("groupswrite", "2/0/1", "1")
		fa.wait(t, 5*time.Second, ga(t, "2/0/1"), knx.GroupValueWrite)
		fb.wait(t, 5*time.Second, ga(t, "2/0/1"), knx.GroupValueWrite)
		k.tool("groupwrite", "2/0/2", "12", "34")
		if v := fa.wait(t, 5*time.Second, ga(t, "2/0/2"), knx.GroupValueWrite).Value(); len(v) != 2 || v[0] != 0x12 || v[1] != 0x34 {
			t.Errorf("long write %x", v)
		}
		k.tool("groupread", "2/0/3")
		fa.wait(t, 5*time.Second, ga(t, "2/0/3"), knx.GroupValueRead)
	})
}
