// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package knx is a KNXnet/IP client and router in pure Go: tunnelling to
// an IP interface over UDP or TCP (link, raw and busmonitor layers), KNX
// IP Secure tunnelling over TCP, routing over multicast with flow control,
// plain or KNX IP Secure, KNX Data Secure group communication
// ([DataSecure]), gateway search (also extended) and description, cEMI
// L_Data frames with group value and management services, datapoint type
// (DPT) encoding, and import of ETS project exports (.knxproj, including
// password-protected ones) and ETS keyrings (.knxkeys).
//
// A connection is a [Tunnel] (from [DialTunnel]) or a [Router] (from
// [ListenRouting]); both are a [Link]. Frames from the bus arrive on the
// OnFrame callback of the options; [GroupFrame] builds the frames to send,
// and [DPT] encodes and decodes their values. [Search] finds gateways.
//
// The package does no logging and keeps no files: errors that do not end a
// connection go to the OnError callback, and ETS files are passed in as
// bytes. The knx-sim module has a gateway and a router to test against.
package knx

import "context"

// Link is bus access through a tunnel or a router.
type Link interface {
	// Send puts a group frame on the bus. A tunnel waits for the gateway's
	// acknowledgement (UDP) and the L_Data.con; a router only sends.
	Send(ctx context.Context, f LData) error
	// Lost is closed when the connection is gone; Err then says why.
	Lost() <-chan struct{}
	// Err is why the connection ended, nil while it is up.
	Err() error
	// Close ends the connection.
	Close()
}

var (
	_ Link = (*Tunnel)(nil)
	_ Link = (*Router)(nil)
)
