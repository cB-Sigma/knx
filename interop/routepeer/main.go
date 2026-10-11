// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command routepeer is this module's side of the routing interop test: it
// joins a KNXnet/IP routing group (optionally KNX IP Secure, optionally
// with KNX Data Secure from a keyring), prints every group frame it
// receives, answers GroupValue_Read of 1/2/3 with 0C33, and sends the
// frames named on standard input:
//
//	SEND <group address> <hex> short|long
//
// It prints "READY keeper=<bool>" once it listens. It is built for Linux
// and run inside the xknx container (multicast does not cross Docker
// Desktop's virtual machine).
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/knx"
)

func main() {
	group := flag.String("group", knx.DefaultMulticast, "routing group")
	iface := flag.String("iface", "eth0", "network interface")
	keyring := flag.String("keyring", "", "ETS keyring for secure routing and Data Secure")
	password := flag.String("password", "", "keyring password")
	secure := flag.Bool("secure", false, "KNX IP Secure routing with the keyring's backbone key")
	source := flag.String("source", "4.0.9", "individual address")
	flag.Parse()

	var out sync.Mutex
	say := func(f string, a ...any) {
		out.Lock()
		fmt.Printf(f+"\n", a...)
		out.Unlock()
	}
	src, err := knx.ParseIndividualAddress(*source)
	if err != nil {
		say("ERROR %v", err)
		os.Exit(1)
	}
	o := knx.RoutingOptions{Group: *group, Interface: *iface, Source: src,
		OnError: func(err error) { say("ERR %v", err) }}
	if *keyring != "" {
		data, err := os.ReadFile(*keyring)
		if err != nil {
			say("ERROR %v", err)
			os.Exit(1)
		}
		k, err := knx.ParseKeyring(data, *password)
		if err != nil {
			say("ERROR %v", err)
			os.Exit(1)
		}
		if o.DataSecure, err = k.DataSecure(""); err != nil {
			say("ERROR %v", err)
			os.Exit(1)
		}
		if *secure {
			o.Secure = &knx.SecureRoutingOptions{BackboneKey: k.BackboneKey, Latency: k.BackboneLatency,
				Serial: [6]byte{0x00, 0xC5, 0x0A, 0x0B, 0x0C, 0x0D}}
			if k.BackboneMulticast != "" && *group == knx.DefaultMulticast {
				o.Group = k.BackboneMulticast + ":3671"
			}
		}
	}
	var r *knx.Router
	ready := make(chan struct{})
	o.OnFrame = func(f knx.LData) {
		if f.Source == src {
			return // our own frame, looped back
		}
		name := map[uint16]string{knx.GroupValueRead: "GroupValueRead", knx.GroupValueResponse: "GroupValueResponse", knx.GroupValueWrite: "GroupValueWrite"}[f.APCI]
		say("RX %s %s %s %s", f.Source, f.Group(), name, hex.EncodeToString(f.Value()))
		if f.APCI == knx.GroupValueRead && f.Group().String() == "1/2/3" {
			go func() {
				<-ready
				_ = r.Send(context.Background(), knx.GroupFrame(0, f.Group(), knx.GroupValueResponse, []byte{0x0C, 0x33}, false))
			}()
		}
	}
	r, err = knx.ListenRouting(o)
	if err != nil {
		say("ERROR %v", err)
		os.Exit(1)
	}
	close(ready)
	defer r.Close()
	say("READY keeper=%v", r.TimeKeeper())
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 || f[0] != "SEND" {
			continue
		}
		ga, err := knx.ParseGroupAddress(f[1])
		v, err2 := hex.DecodeString(f[2])
		if err != nil || err2 != nil {
			say("ERROR bad command %q", sc.Text())
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = r.Send(ctx, knx.GroupFrame(0, ga, knx.GroupValueWrite, v, f[3] == "short"))
		cancel()
		say("SENT %s %v", ga, err)
	}
	b, l := r.Busy()
	say("END busy=%d lost=%d", b, l)
}
