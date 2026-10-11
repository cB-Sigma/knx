package knx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// TunnelOptions tune a tunnelling connection.
type TunnelOptions struct {
	// Heartbeat is the interval of CONNECTIONSTATE_REQUESTs (default 60s).
	Heartbeat time.Duration
	// Timeout bounds the wait for CONNECT, CONNECTIONSTATE, DISCONNECT and
	// DESCRIPTION responses (default 10s) and for an L_Data.con (default 3s,
	// capped by Timeout).
	Timeout time.Duration
	// AckTimeout is the wait for a TUNNELLING_ACK before the one repeat
	// (default 1s).
	AckTimeout time.Duration
	// NAT sends 0.0.0.0:0 endpoints so the gateway answers the sender's
	// address (for gateways behind or in front of address translation).
	NAT bool
	// TCP tunnels over a KNXnet/IP TCP connection (core v2) instead of UDP:
	// frames are delimited by their total length, endpoints are the TCP
	// route-back HPAI, and TUNNELLING_REQUESTs are not acknowledged (the
	// stream is reliable). Closing the stream ends the tunnel.
	TCP bool
	// Secure runs the tunnel inside a KNX IP Secure session (implies TCP).
	Secure *SecureOptions
	// OnFrame receives every L_Data frame from the gateway (indications and
	// confirmations).
	OnFrame func(LData)
	// OnError receives protocol problems worth logging.
	OnError func(error)
}

// Tunnel is a KNXnet/IP tunnelling connection (link layer) to a gateway.
type Tunnel struct {
	opts    TunnelOptions
	fc      frameConn
	tcp     bool
	control *net.UDPAddr // gateway control endpoint
	data    *net.UDPAddr // gateway data endpoint
	local   HPAI
	Channel byte
	Address IndividualAddress // assigned to this tunnel
	Gateway *Description      // from DESCRIPTION_REQUEST, when the gateway answered

	sendMu sync.Mutex // one outstanding TUNNELLING_REQUEST
	mu     sync.Mutex
	txSeq  byte
	rxSeq  byte
	acks   chan TunnelAck
	states chan ChannelResponse
	cons   map[GroupAddress]chan LData
	lost   chan struct{}
	err    error
	closed bool
	// peerClosed: the gateway sent DISCONNECT_REQUEST.
	peerClosed bool
	wg         sync.WaitGroup
	cancel     context.CancelFunc
}

// ErrConnectionLost is wrapped by errors that end a tunnel.
var ErrConnectionLost = errors.New("knx: tunnelling connection lost")

func (o *TunnelOptions) defaults() {
	if o.Heartbeat <= 0 {
		o.Heartbeat = 60 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.AckTimeout <= 0 {
		o.AckTimeout = time.Second
	}
}

// DialTunnel opens a tunnelling connection to the gateway at addr
// ("host:port"): it asks for a description (optional, failures ignored),
// connects and starts the heartbeat. Close ends it with a DISCONNECT.
func DialTunnel(ctx context.Context, addr string, o TunnelOptions) (*Tunnel, error) {
	o.defaults()
	if o.Secure != nil {
		o.TCP = true
	}
	t := &Tunnel{opts: o, tcp: o.TCP,
		acks: make(chan TunnelAck, 8), states: make(chan ChannelResponse, 4),
		cons: map[GroupAddress]chan LData{}, lost: make(chan struct{})}
	if o.TCP {
		tc, err := dialTCP(ctx, addr, o.Timeout, o.OnError)
		if err != nil {
			return nil, err
		}
		t.fc = tc
		if o.Secure != nil {
			sc, err := secureHandshake(ctx, tc, *o.Secure, o.Timeout, o.OnError)
			if err != nil {
				tc.close()
				return nil, err
			}
			t.fc = sc
		}
		t.local = TCPHPAI()
	} else {
		raddr, err := net.ResolveUDPAddr("udp4", addr)
		if err != nil {
			return nil, fmt.Errorf("knx: gateway address %q: %w", addr, err)
		}
		conn, err := localSocket(raddr)
		if err != nil {
			return nil, err
		}
		t.control, t.data = raddr, raddr
		t.fc = newUDPConn(conn, o.OnError)
		if o.NAT {
			t.local = HPAIFrom(nil)
		} else {
			t.local = HPAIFrom(conn.LocalAddr().(*net.UDPAddr))
		}
	}
	if err := t.connect(ctx); err != nil {
		t.fc.close()
		return nil, err
	}
	rctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.wg.Add(2)
	go func() { defer t.wg.Done(); t.readLoop() }()
	go func() { defer t.wg.Done(); t.heartbeat(rctx) }()
	return t, nil
}

// localSocket opens an unconnected UDP socket on the interface that routes
// to the gateway, so the HPAI carries a reachable address.
func localSocket(raddr *net.UDPAddr) (*net.UDPConn, error) {
	var lip net.IP
	if probe, err := net.DialUDP("udp4", nil, raddr); err == nil {
		lip = probe.LocalAddr().(*net.UDPAddr).IP
		_ = probe.Close()
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lip})
	if err != nil {
		return nil, fmt.Errorf("knx: opening a UDP socket: %w", err)
	}
	return conn, nil
}

// exchange sends a frame to the control endpoint and waits for a reply of
// the given service (used before the read loop runs).
func (t *Tunnel) exchange(ctx context.Context, f Frame, want uint16) (Frame, error) {
	if err := t.fc.write(f, t.control); err != nil {
		return Frame{}, err
	}
	fr, err := awaitFrame(ctx, t.fc.recv(), t.opts.Timeout, func(f Frame) bool { return f.Service == want })
	if errors.Is(err, ErrConnectionLost) {
		if e := t.fc.err(); e != nil {
			err = e
		}
	}
	return fr, err
}

func (t *Tunnel) connect(ctx context.Context) error {
	// A description first (UDP only): it names the gateway and says whether
	// it tunnels at all. Old gateways may not answer; that is not fatal.
	if t.tcp {
		// Over TCP the tunnel is asked for directly.
	} else if fr, err := t.exchange(ctx, DescriptionRequest(t.local), SvcDescriptionResponse); err == nil {
		if d, err := ParseDescriptionResponse(fr.Body); err == nil {
			t.Gateway = &d
			if len(d.Families) > 0 && !d.Supports(FamilyTunnelling) {
				return fmt.Errorf("knx: gateway %s (%q) does not offer tunnelling", t.control, d.Device.FriendlyName)
			}
		}
	} else if ctx.Err() != nil {
		return ctx.Err()
	}
	fr, err := t.exchange(ctx, ConnectRequest{Control: t.local, Data: t.local}.Frame(), SvcConnectResponse)
	if err != nil {
		return fmt.Errorf("knx: connecting to the gateway: %w", err)
	}
	cr, err := ParseConnectResponse(fr.Body)
	if err != nil {
		return err
	}
	if cr.Status != StatusOK {
		return fmt.Errorf("knx: the gateway refused the tunnel: %s", statusText(cr.Status))
	}
	t.Channel, t.Address = cr.Channel, cr.Address
	if !t.tcp {
		t.data = cr.Data.UDPAddr(t.control)
	}
	return nil
}

func statusText(s byte) string {
	switch s {
	case StatusConnectionID:
		return "unknown connection (0x21)"
	case StatusConnectionType:
		return "connection type not supported (0x22)"
	case StatusConnectionOption:
		return "connection option not supported (0x23)"
	case StatusNoMoreConns:
		return "no more connections (0x24)"
	case StatusDataConnection:
		return "data connection error (0x26)"
	case StatusKNXConnection:
		return "KNX subnetwork connection error (0x27)"
	case StatusTunnellingLayer:
		return "tunnelling layer not supported (0x29)"
	case StatusSequenceNumber:
		return "wrong sequence number (0x04)"
	}
	return fmt.Sprintf("status %#02x", s)
}

// fail ends the connection once, recording why.
func (t *Tunnel) fail(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.err != nil {
		return
	}
	t.err = err
	close(t.lost)
}

// Lost is closed when the tunnel has ended; Err then says why.
func (t *Tunnel) Lost() <-chan struct{} { return t.lost }

// Err is why the tunnel ended, nil while it is up.
func (t *Tunnel) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

func (t *Tunnel) send(f Frame, to *net.UDPAddr) error {
	return t.fc.write(f, to)
}

func (t *Tunnel) readLoop() {
	for {
		r, ok := <-t.fc.recv()
		if !ok {
			err := t.fc.err()
			if err == nil {
				err = ErrConnectionLost
			}
			t.fail(err)
			return
		}
		fr, from := r.f, r.from
		body := fr.Body
		switch fr.Service {
		case SvcTunnellingAck:
			a, err := ParseTunnelAck(body)
			if err == nil && a.Channel == t.Channel {
				select {
				case t.acks <- a:
				default:
				}
			}
		case SvcConnectionStateResponse:
			r, err := ParseChannelResponse(body)
			if err == nil && r.Channel == t.Channel {
				select {
				case t.states <- r:
				default:
				}
			}
		case SvcTunnellingRequest:
			t.onTunnelRequest(body, from)
		case SvcDisconnectRequest:
			r, err := ParseChannelRequest(body)
			if err == nil && r.Channel == t.Channel {
				_ = t.send(ChannelResponse{Channel: t.Channel}.Frame(SvcDisconnectResponse), t.control)
				t.mu.Lock()
				t.peerClosed = true
				t.mu.Unlock()
				t.fail(fmt.Errorf("%w: the gateway closed the connection", ErrConnectionLost))
				return
			}
		case SvcDisconnectResponse:
			// Our own disconnect finished.
		}
	}
}

func (t *Tunnel) report(err error) {
	if t.opts.OnError != nil {
		t.opts.OnError(err)
	}
}

// onTunnelRequest acknowledges and delivers a frame from the gateway. The
// expected sequence number is delivered and advances the counter; the one
// before it is a repeat of a frame whose ack was lost, so it is acked again
// and dropped; anything else is dropped without an ack.
func (t *Tunnel) onTunnelRequest(body []byte, from *net.UDPAddr) {
	r, err := ParseTunnelRequest(body)
	if err != nil {
		t.report(err)
		return
	}
	if r.Channel != t.Channel {
		return
	}
	if t.tcp {
		// Over TCP (core v2) requests are not acknowledged nor repeated:
		// every one is delivered.
		t.deliverCEMI(r.CEMI)
		return
	}
	t.mu.Lock()
	expected := t.rxSeq
	deliver := false
	ack := true
	switch r.Seq {
	case expected:
		t.rxSeq++
		deliver = true
	case expected - 1:
	default:
		ack = false
	}
	t.mu.Unlock()
	if ack {
		_ = t.send(TunnelAck{Channel: t.Channel, Seq: r.Seq, Status: StatusOK}.Frame(), t.data)
	}
	if !deliver {
		return
	}
	t.deliverCEMI(r.CEMI)
}

func (t *Tunnel) deliverCEMI(cemi []byte) {
	f, err := ParseLData(cemi)
	if err != nil {
		if !errors.Is(err, ErrNotLData) {
			t.report(err)
		}
		return
	}
	if f.Code == LDataCon && f.GroupTarget {
		t.mu.Lock()
		ch := t.cons[f.Group()]
		t.mu.Unlock()
		if ch != nil {
			select {
			case ch <- f:
			default:
			}
		}
	}
	if t.opts.OnFrame != nil {
		t.opts.OnFrame(f)
	}
}

func (t *Tunnel) heartbeat(ctx context.Context) {
	tick := time.NewTicker(t.opts.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.lost:
			return
		case <-tick.C:
		}
		if err := t.checkState(ctx); err != nil {
			t.fail(err)
			return
		}
	}
}

// checkState sends up to three CONNECTIONSTATE_REQUESTs, each waiting
// Timeout for the answer.
func (t *Tunnel) checkState(ctx context.Context) error {
	var last string
	for attempt := 0; attempt < 3; attempt++ {
		// Drop stale answers.
		for len(t.states) > 0 {
			<-t.states
		}
		if err := t.send(ChannelRequest{Channel: t.Channel, Control: t.local}.Frame(SvcConnectionStateRequest), t.control); err != nil {
			last = err.Error()
			continue
		}
		timer := time.NewTimer(t.opts.Timeout)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-t.lost:
			timer.Stop()
			return nil
		case r := <-t.states:
			timer.Stop()
			if r.Status == StatusOK {
				return nil
			}
			last = statusText(r.Status)
			if r.Status == StatusConnectionID {
				return fmt.Errorf("%w: the gateway no longer knows channel %d", ErrConnectionLost, t.Channel)
			}
		case <-timer.C:
			last = "no answer within " + t.opts.Timeout.String()
		}
	}
	return fmt.Errorf("%w: 3 heartbeats failed (%s)", ErrConnectionLost, last)
}

// Send transmits a group frame through the tunnel: a TUNNELLING_REQUEST
// acknowledged within AckTimeout (repeated once; over TCP there is no ack),
// then the L_Data.con for the destination.
func (t *Tunnel) Send(ctx context.Context, f LData) error {
	f.Code = LDataReq
	g := f.Group()
	con := make(chan LData, 1)
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if err := t.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	t.cons[g] = con
	seq := t.txSeq
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.cons, g)
		t.mu.Unlock()
	}()
	req := TunnelRequest{Channel: t.Channel, Seq: seq, CEMI: f.Encode()}.Frame()
	acked := false
	if t.tcp {
		// No TUNNELLING_ACK over TCP: the stream delivers or fails.
		if err := t.send(req, nil); err != nil {
			t.fail(fmt.Errorf("%w: %v", ErrConnectionLost, err))
			return err
		}
		acked = true
	}
	for attempt := 0; attempt < 2 && !acked; attempt++ {
		for len(t.acks) > 0 {
			<-t.acks
		}
		if err := t.send(req, t.data); err != nil {
			return err
		}
		timer := time.NewTimer(t.opts.AckTimeout)
	wait:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-t.lost:
				timer.Stop()
				return t.Err()
			case a := <-t.acks:
				if a.Seq != seq {
					continue
				}
				timer.Stop()
				if a.Status != StatusOK {
					return fmt.Errorf("knx: the gateway rejected the frame: %s", statusText(a.Status))
				}
				acked = true
				break wait
			case <-timer.C:
				break wait
			}
		}
	}
	if !acked {
		err := fmt.Errorf("%w: no TUNNELLING_ACK for sequence %d after one repeat", ErrConnectionLost, seq)
		t.fail(err)
		return err
	}
	t.mu.Lock()
	t.txSeq++
	t.mu.Unlock()
	wait := min(3*time.Second, t.opts.Timeout)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.lost:
		return t.Err()
	case c := <-con:
		if !c.Confirmed() {
			return fmt.Errorf("knx: the gateway could not send to %s (negative L_Data.con)", g)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("knx: no L_Data.con for %s within %s", g, wait)
	}
}

// Close disconnects (best effort) and releases the socket.
func (t *Tunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	peerClosed := t.peerClosed
	t.mu.Unlock()
	// Also after a lost connection: the gateway may still hold the channel.
	if !peerClosed {
		_ = t.send(ChannelRequest{Channel: t.Channel, Control: t.local}.Frame(SvcDisconnectRequest), t.control)
	}
	t.fail(fmt.Errorf("%w: closed", ErrConnectionLost))
	if t.cancel != nil {
		t.cancel()
	}
	t.fc.close()
	t.wg.Wait()
}
