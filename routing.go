package knx

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// RoutingOptions configure KNXnet/IP routing.
type RoutingOptions struct {
	// Group is where ROUTING_INDICATIONs go (default 224.0.23.12:3671). A
	// unicast address is allowed for point-to-point use and tests; Listen
	// then names the local address to receive on.
	Group string
	// Interface is the network interface for multicast (default: the
	// system's choice).
	Interface string
	// Listen is the local receive address for a unicast Group.
	Listen string
	// Source is the individual address frames are sent from (default
	// 15.15.255).
	Source  IndividualAddress
	OnFrame func(LData)
	OnError func(error)

	// MinInterval is the least time between two indications this router
	// sends (default 20ms, the pacing KNX IP routers expect; negative
	// turns pacing off).
	MinInterval time.Duration
	// OnBusy is told of every ROUTING_BUSY received; Send pauses for the
	// wait time it names (flow control) whether or not this is set.
	OnBusy func(RoutingBusy)
	// OnLostMessage is told of every ROUTING_LOST_MESSAGE received.
	OnLostMessage func(RoutingLostMessage)
	// Secure runs KNX IP Secure routing: every frame travels in a
	// SECURE_WRAPPER keyed with the backbone key, and plain frames are
	// discarded.
	Secure *SecureRoutingOptions
	// DataSecure seals frames to secured group addresses and opens secured
	// frames received (KNX Data Secure).
	DataSecure *DataSecure
}

// SecureRoutingOptions configure KNX IP Secure routing.
type SecureRoutingOptions struct {
	// BackboneKey is the 16-byte backbone key (Keyring.BackboneKey).
	BackboneKey []byte
	// Latency is the backbone's latency tolerance (default 1000ms; the
	// keyring gives it as Keyring.BackboneLatency).
	Latency time.Duration
	// Serial is this node's serial number in its wrappers (default: a
	// random one).
	Serial [6]byte
}

// Router sends and receives ROUTING_INDICATIONs. Routing has no
// acknowledgements or confirmations: Send returns once the datagram left.
type Router struct {
	opts  RoutingOptions
	rx    *net.UDPConn
	tx    *net.UDPConn
	group *net.UDPAddr
	lost  chan struct{}
	mu    sync.Mutex
	err   error
	wg    sync.WaitGroup

	sendMu   sync.Mutex
	lastSend time.Time
	// flow control (guarded by mu)
	pausedUntil time.Time
	busySeen    time.Time
	busyCount   int
	busy, lostN int

	sec      *secureTimer
	recent   [32]string
	recentAt int
}

// ListenRouting joins the routing group (or binds the unicast listen
// address) and starts receiving. With Secure set it first synchronises
// the secure timer with the other routers (up to a few seconds; it becomes
// the time keeper when nobody answers).
func ListenRouting(o RoutingOptions) (*Router, error) {
	if o.Group == "" {
		o.Group = DefaultMulticast
	}
	if o.Source == 0 {
		o.Source = 0xFFFF
	}
	if o.MinInterval == 0 {
		o.MinInterval = 20 * time.Millisecond
	}
	g, err := net.ResolveUDPAddr("udp4", o.Group)
	if err != nil {
		return nil, fmt.Errorf("knx: routing group %q: %w", o.Group, err)
	}
	r := &Router{opts: o, group: g, lost: make(chan struct{})}
	if o.Secure != nil {
		if len(o.Secure.BackboneKey) != 16 && len(o.Secure.BackboneKey) != 32 {
			return nil, errors.New("knx: secure routing needs a 16-byte backbone key")
		}
		so := *o.Secure
		if so.Latency <= 0 {
			so.Latency = time.Second
		}
		if so.Serial == ([6]byte{}) {
			_, _ = crand.Read(so.Serial[:])
		}
		r.sec = newSecureTimer(so, r.writeRaw)
	}
	if g.IP.IsMulticast() {
		var ifi *net.Interface
		if o.Interface != "" {
			if ifi, err = net.InterfaceByName(o.Interface); err != nil {
				return nil, fmt.Errorf("knx: interface %q: %w", o.Interface, err)
			}
		}
		if r.rx, err = net.ListenMulticastUDP("udp4", ifi, g); err != nil {
			return nil, fmt.Errorf("knx: joining %s: %w", g, err)
		}
		var laddr *net.UDPAddr
		if ifi != nil {
			if addrs, err := ifi.Addrs(); err == nil {
				for _, a := range addrs {
					if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil {
						laddr = &net.UDPAddr{IP: ip.IP}
						break
					}
				}
			}
		}
		if r.tx, err = net.ListenUDP("udp4", laddr); err != nil {
			_ = r.rx.Close()
			return nil, err
		}
	} else {
		if o.Listen == "" {
			return nil, errors.New("knx: a unicast routing group needs a listen address")
		}
		la, err := net.ResolveUDPAddr("udp4", o.Listen)
		if err != nil {
			return nil, fmt.Errorf("knx: listen address %q: %w", o.Listen, err)
		}
		if r.rx, err = net.ListenUDP("udp4", la); err != nil {
			return nil, fmt.Errorf("knx: listening on %s: %w", la, err)
		}
		r.tx = r.rx
	}
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.readLoop() }()
	if r.sec != nil {
		r.sec.synchronise()
	}
	return r, nil
}

// LocalAddr is the receive socket's address.
func (r *Router) LocalAddr() *net.UDPAddr { return r.rx.LocalAddr().(*net.UDPAddr) }

func (r *Router) report(err error) {
	if r.opts.OnError != nil {
		r.opts.OnError(err)
	}
}

func (r *Router) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := r.rx.ReadFromUDP(buf)
		if err != nil {
			r.mu.Lock()
			if r.err == nil {
				r.err = fmt.Errorf("knx: routing socket: %w", err)
				close(r.lost)
			}
			r.mu.Unlock()
			if r.sec != nil {
				r.sec.stop()
			}
			return
		}
		if r.sec != nil && r.ownEcho(buf[:n]) {
			continue // our own datagram, looped back by the multicast group
		}
		fr, err := ParseFrame(buf[:n])
		if err != nil {
			continue
		}
		if r.sec != nil {
			switch fr.Service {
			case SvcTimerNotify:
				r.sec.onNotify(fr.Body)
				continue
			case SvcSecureWrapper:
				inner, ok := r.sec.unwrap(fr.Body)
				if !ok {
					continue
				}
				fr = inner
			case SvcRoutingIndication, SvcRoutingBusy, SvcRoutingLostMessage:
				r.report(fmt.Errorf("%w: plain routing frame %#04x discarded on a secure backbone", ErrSecure, fr.Service))
				continue
			default:
				continue
			}
		}
		r.handle(fr)
	}
}

func (r *Router) handle(fr Frame) {
	switch fr.Service {
	case SvcRoutingIndication:
		f, err := ParseLData(fr.Body)
		if err != nil {
			if !errors.Is(err, ErrNotLData) {
				r.report(err)
			}
			return
		}
		if ds := r.opts.DataSecure; ds != nil {
			if f, err = ds.Open(f); err != nil {
				r.report(err)
				return
			}
		}
		if r.opts.OnFrame != nil {
			r.opts.OnFrame(f)
		}
	case SvcRoutingBusy:
		b, err := ParseRoutingBusy(fr.Body)
		if err != nil {
			r.report(err)
			return
		}
		r.onBusy(b)
		if r.opts.OnBusy != nil {
			r.opts.OnBusy(b)
		}
	case SvcRoutingLostMessage:
		l, err := ParseRoutingLostMessage(fr.Body)
		if err != nil {
			r.report(err)
			return
		}
		r.mu.Lock()
		r.lostN += int(l.Lost)
		r.mu.Unlock()
		if r.opts.OnLostMessage != nil {
			r.opts.OnLostMessage(l)
		}
	}
}

// Flow control (KNX Standard volume 3 part 8 chapter 5, routing): a
// ROUTING_BUSY stops sending for its wait time. Several busy frames in a
// row (more than 10ms apart) raise a counter N; the pause then gets a
// random extension of up to N × 50ms, and after it N falls by one every
// 5ms once N × 100ms have passed. A busy frame whose wait ends before the
// current pause does is only counted.
func (r *Router) onBusy(b RoutingBusy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.busy++
	if r.busyCount > 0 && now.After(r.pausedUntil) {
		// Fade N out: after N × 100ms, one per 5ms.
		fade := r.pausedUntil.Add(time.Duration(r.busyCount) * 100 * time.Millisecond)
		if now.After(fade) {
			r.busyCount = max(0, r.busyCount-int(now.Sub(fade)/(5*time.Millisecond)))
		}
	}
	prev := r.busySeen
	r.busySeen = now
	if now.Before(r.pausedUntil) {
		if now.Sub(prev) > 10*time.Millisecond {
			r.busyCount++
		}
		if r.pausedUntil.Sub(now) >= b.WaitTime {
			return
		}
	}
	ext := time.Duration(rand.Float64() * float64(r.busyCount) * float64(50*time.Millisecond))
	r.pausedUntil = now.Add(b.WaitTime + ext)
}

// Busy counts ROUTING_BUSY frames received; Lost counts the frames other
// routers reported lost (ROUTING_LOST_MESSAGE).
func (r *Router) Busy() (busyFrames, lostMessages int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.busy, r.lostN
}

// pace waits for the end of a busy pause and the least interval.
func (r *Router) pace(ctx context.Context) error {
	for {
		r.mu.Lock()
		until := r.pausedUntil
		r.mu.Unlock()
		if gap := r.opts.MinInterval; gap > 0 && !r.lastSend.IsZero() {
			if t := r.lastSend.Add(gap); t.After(until) {
				until = t
			}
		}
		d := time.Until(until)
		if d <= 0 {
			return nil
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-r.lost:
			t.Stop()
			return r.Err()
		case <-t.C:
		}
	}
}

// writeRaw sends a frame to the group, wrapped on a secure backbone
// (timer notifications go out as they are).
func (r *Router) writeRaw(f Frame) error {
	b := f.Encode()
	if r.sec != nil && f.Service != SvcTimerNotify {
		b = r.sec.wrap(f).Encode()
	}
	if r.sec != nil {
		r.mu.Lock()
		r.recent[r.recentAt%len(r.recent)] = string(b)
		r.recentAt++
		r.mu.Unlock()
	}
	_, err := r.tx.WriteToUDP(b, r.group)
	return err
}

// ownEcho reports a datagram this router sent recently.
func (r *Router) ownEcho(b []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.recent {
		if s == string(b) {
			return true
		}
	}
	return false
}

// Send multicasts an L_Data.ind, after any busy pause and at least
// MinInterval after the previous one; with DataSecure set, a frame to a
// secured group is sealed first.
func (r *Router) Send(ctx context.Context, f LData) error {
	f.Code = LDataInd
	if f.Source == 0 {
		f.Source = r.opts.Source
	}
	if ds := r.opts.DataSecure; ds != nil {
		var err error
		if f, err = ds.Seal(f); err != nil {
			return err
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	if err := r.pace(ctx); err != nil {
		return err
	}
	r.lastSend = time.Now()
	return r.writeRaw(RoutingIndication(f.Encode()))
}

// SendBusy multicasts a ROUTING_BUSY (for routers and simulators whose
// queue is filling up).
func (r *Router) SendBusy(wait time.Duration) error {
	return r.writeRaw(RoutingBusy{WaitTime: wait}.Frame())
}

// SendLostMessage multicasts a ROUTING_LOST_MESSAGE.
func (r *Router) SendLostMessage(lost uint16) error {
	return r.writeRaw(RoutingLostMessage{Lost: lost}.Frame())
}

// TimeKeeper reports whether this router keeps the secure backbone's time
// (false without Secure).
func (r *Router) TimeKeeper() bool {
	if r.sec == nil {
		return false
	}
	return r.sec.keeper()
}

// Lost is closed when the router socket has failed or been closed.
func (r *Router) Lost() <-chan struct{} { return r.lost }

// Err is why the router stopped, nil while it runs.
func (r *Router) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Close stops the router.
func (r *Router) Close() {
	if r.sec != nil {
		r.sec.stop()
	}
	_ = r.rx.Close()
	if r.tx != r.rx {
		_ = r.tx.Close()
	}
	r.wg.Wait()
}

// ---- discovery ---------------------------------------------------------------

// Search sends a SEARCH_REQUEST to target (default the routing multicast
// group; a gateway's unicast address works too) and collects the answers
// that arrive within wait.
func Search(ctx context.Context, target string, wait time.Duration) ([]Description, error) {
	return search(ctx, target, wait, func(h HPAI) Frame { return SearchRequest(h) }, SvcSearchResponse)
}

// SearchExtended sends a SEARCH_REQUEST_EXTENDED (KNXnet/IP core v2) with
// search parameter blocks, such as SRPByService(FamilyTunnelling, 2) or
// SRPWantDIBs(DIBTunnellingInfo), and collects the answers that arrive
// within wait. Only gateways of core v2 answer it; the answers carry the
// secured families and tunnelling slots when the gateway sends them.
func SearchExtended(ctx context.Context, target string, wait time.Duration, srps ...SRP) ([]Description, error) {
	return search(ctx, target, wait, func(h HPAI) Frame { return SearchRequestExtended(h, srps...) }, SvcSearchResponseExtended)
}

func search(ctx context.Context, target string, wait time.Duration, req func(HPAI) Frame, want uint16) ([]Description, error) {
	if target == "" {
		target = DefaultMulticast
	}
	to, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, fmt.Errorf("knx: search target %q: %w", target, err)
	}
	conn, err := localSocket(to)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.WriteToUDP(req(HPAIFrom(conn.LocalAddr().(*net.UDPAddr))).Encode(), to); err != nil {
		return nil, fmt.Errorf("knx: sending the search request: %w", err)
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	var out []Description
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return out, nil
			}
			return out, err
		}
		fr, err := ParseFrame(buf[:n])
		if err != nil || fr.Service != want {
			continue
		}
		d, err := ParseSearchResponse(fr.Body)
		if err != nil {
			continue
		}
		if d.Control.Zero() || d.Control.Addr.Addr().IsUnspecified() {
			d.Control = HPAIFrom(from)
		}
		out = append(out, d)
	}
}
