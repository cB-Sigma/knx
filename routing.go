package knx

import (
	"context"
	"errors"
	"fmt"
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
}

// ListenRouting joins the routing group (or binds the unicast listen
// address) and starts receiving.
func ListenRouting(o RoutingOptions) (*Router, error) {
	if o.Group == "" {
		o.Group = DefaultMulticast
	}
	if o.Source == 0 {
		o.Source = 0xFFFF
	}
	g, err := net.ResolveUDPAddr("udp4", o.Group)
	if err != nil {
		return nil, fmt.Errorf("knx: routing group %q: %w", o.Group, err)
	}
	r := &Router{opts: o, group: g, lost: make(chan struct{})}
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
		if r.tx, err = net.ListenUDP("udp4", nil); err != nil {
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
	return r, nil
}

// LocalAddr is the receive socket's address.
func (r *Router) LocalAddr() *net.UDPAddr { return r.rx.LocalAddr().(*net.UDPAddr) }

func (r *Router) readLoop() {
	buf := make([]byte, 1024)
	for {
		n, _, err := r.rx.ReadFromUDP(buf)
		if err != nil {
			r.mu.Lock()
			if r.err == nil {
				r.err = fmt.Errorf("knx: routing socket: %w", err)
				close(r.lost)
			}
			r.mu.Unlock()
			return
		}
		fr, err := ParseFrame(buf[:n])
		if err != nil || fr.Service != SvcRoutingIndication {
			continue
		}
		f, err := ParseLData(fr.Body)
		if err != nil {
			if !errors.Is(err, ErrNotLData) && r.opts.OnError != nil {
				r.opts.OnError(err)
			}
			continue
		}
		if r.opts.OnFrame != nil {
			r.opts.OnFrame(f)
		}
	}
}

// Send multicasts an L_Data.ind.
func (r *Router) Send(_ context.Context, f LData) error {
	f.Code = LDataInd
	if f.Source == 0 {
		f.Source = r.opts.Source
	}
	_, err := r.tx.WriteToUDP(RoutingIndication(f.Encode()).Encode(), r.group)
	return err
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
	if _, err := conn.WriteToUDP(SearchRequest(HPAIFrom(conn.LocalAddr().(*net.UDPAddr))).Encode(), to); err != nil {
		return nil, fmt.Errorf("knx: sending the search request: %w", err)
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	var out []Description
	buf := make([]byte, 1024)
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
		if err != nil || fr.Service != SvcSearchResponse {
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
