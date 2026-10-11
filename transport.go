package knx

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// A frameConn carries KNXnet/IP frames: datagrams over UDP, a stream over
// TCP (KNXnet/IP core v2), or a KNX IP Secure session over TCP.
type frameConn interface {
	// write sends a frame; to is the UDP destination (ignored on streams).
	write(f Frame, to *net.UDPAddr) error
	// recv delivers received frames; it is closed when the connection ends,
	// and err then says why.
	recv() <-chan rxFrame
	err() error
	close()
}

type rxFrame struct {
	f    Frame
	from *net.UDPAddr
}

// connBase is the delivery side shared by the transports.
type connBase struct {
	ch      chan rxFrame
	stop    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	e       error
	wg      sync.WaitGroup
	onError func(error)
}

func newConnBase(onError func(error)) connBase {
	return connBase{ch: make(chan rxFrame, 32), stop: make(chan struct{}), onError: onError}
}

func (c *connBase) recv() <-chan rxFrame { return c.ch }

func (c *connBase) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.e
}

func (c *connBase) report(err error) {
	if c.onError != nil {
		c.onError(err)
	}
}

// deliver hands a frame to the reader; false once the connection is closed.
func (c *connBase) deliver(r rxFrame) bool {
	select {
	case c.ch <- r:
		return true
	case <-c.stop:
		return false
	}
}

// end records why the connection ended and closes the channel (called by
// the reader goroutine only).
func (c *connBase) end(err error) {
	c.mu.Lock()
	if c.e == nil {
		c.e = err
	}
	c.mu.Unlock()
	close(c.ch)
}

// ---- UDP ---------------------------------------------------------------------

type udpConn struct {
	connBase
	c *net.UDPConn
}

func newUDPConn(c *net.UDPConn, onError func(error)) *udpConn {
	u := &udpConn{connBase: newConnBase(onError), c: c}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		buf := make([]byte, 1024)
		for {
			n, from, err := u.c.ReadFromUDP(buf)
			if err != nil {
				u.end(fmt.Errorf("%w: %v", ErrConnectionLost, err))
				return
			}
			fr, err := ParseFrame(buf[:n])
			if err != nil {
				u.report(err)
				continue
			}
			fr.Body = append([]byte(nil), fr.Body...)
			if !u.deliver(rxFrame{fr, from}) {
				u.end(fmt.Errorf("%w: closed", ErrConnectionLost))
				return
			}
		}
	}()
	return u
}

func (u *udpConn) write(f Frame, to *net.UDPAddr) error {
	_, err := u.c.WriteToUDP(f.Encode(), to)
	return err
}

func (u *udpConn) close() {
	u.once.Do(func() { close(u.stop) })
	_ = u.c.Close()
	u.wg.Wait()
}

// ---- TCP ---------------------------------------------------------------------

// ReadStreamFrame reads one frame from a KNXnet/IP TCP stream: the 6-byte
// header, then total length minus 6 bytes of body. Frame boundaries come
// only from the header's total length.
func ReadStreamFrame(r io.Reader) (Frame, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	if h[0] != headerLen || h[1] != protocolVersion {
		return Frame{}, fmt.Errorf("knxnet/ip: stream header length %#x / version %#x not supported", h[0], h[1])
	}
	total := int(binary.BigEndian.Uint16(h[4:]))
	if total < headerLen {
		return Frame{}, fmt.Errorf("knxnet/ip: stream frame total length %d", total)
	}
	body := make([]byte, total-headerLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	return Frame{Service: binary.BigEndian.Uint16(h[2:]), Body: body}, nil
}

type tcpConn struct {
	connBase
	c   net.Conn
	wmu sync.Mutex
}

func dialTCP(ctx context.Context, addr string, timeout time.Duration, onError func(error)) (*tcpConn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("knx: TCP connection to %s: %w", addr, err)
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	t := &tcpConn{connBase: newConnBase(onError), c: c}
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		r := bufio.NewReader(c)
		for {
			fr, err := ReadStreamFrame(r)
			if err != nil {
				// A framing error leaves the stream unusable: end it.
				t.end(fmt.Errorf("%w: %v", ErrConnectionLost, err))
				return
			}
			if !t.deliver(rxFrame{f: fr}) {
				t.end(fmt.Errorf("%w: closed", ErrConnectionLost))
				return
			}
		}
	}()
	return t, nil
}

func (t *tcpConn) write(f Frame, _ *net.UDPAddr) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_ = t.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := t.c.Write(f.Encode())
	return err
}

func (t *tcpConn) close() {
	t.once.Do(func() { close(t.stop) })
	_ = t.c.Close()
	t.wg.Wait()
}

// ---- KNX IP Secure session -----------------------------------------------------

// SecureOptions configure a KNX IP Secure tunnelling session.
type SecureOptions struct {
	// UserID is the tunnelling user (2 and up; 1 is the management user).
	UserID byte
	// PasswordHash is UserPasswordHash of the user's password.
	PasswordHash []byte
	// DeviceAuth is DeviceAuthCode of the gateway's device authentication
	// password; nil skips the check of SESSION_RESPONSE (not recommended).
	DeviceAuth []byte
	// Keepalive is the idle time after which a SESSION_STATUS keepalive is
	// sent (default 50s, below the 60s session timeout).
	Keepalive time.Duration
	// Serial is the serial number put in our wrappers.
	Serial [6]byte
}

// DefaultSerial is the serial number of our secure wrappers.
var DefaultSerial = [6]byte{0x00, 0x00, 'S', 'G', 'M', 'A'}

type secureConn struct {
	connBase
	in        *tcpConn
	key       []byte
	sessionID uint16
	serial    [6]byte
	keepalive time.Duration

	wmu      sync.Mutex
	txSeq    uint64
	lastSend time.Time
	lastRx   int64 // highest accepted sequence; -1 before the first
}

// secureHandshake runs SESSION_REQUEST / RESPONSE / AUTHENTICATE / STATUS
// on a fresh TCP connection and returns the session.
func secureHandshake(ctx context.Context, in *tcpConn, o SecureOptions, timeout time.Duration, onError func(error)) (*secureConn, error) {
	priv, err := NewSessionKeyPair()
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	if err := in.write(SessionRequestFrame(pub), nil); err != nil {
		return nil, err
	}
	fr, err := awaitFrame(ctx, in.recv(), timeout, func(f Frame) bool { return f.Service == SvcSessionResponse })
	if err != nil {
		return nil, fmt.Errorf("knx ip secure: waiting for SESSION_RESPONSE: %w", err)
	}
	resp, err := ParseSessionResponse(fr.Body)
	if err != nil {
		return nil, err
	}
	if o.DeviceAuth != nil && !CheckMAC(resp.MAC, SessionResponseMAC(o.DeviceAuth, resp.SessionID, pub, resp.ServerPub)) {
		return nil, errors.New("knx ip secure: the gateway's SESSION_RESPONSE failed the device authentication check (wrong device authentication code, or not the expected gateway)")
	}
	key, err := SharedSessionKey(priv, resp.ServerPub)
	if err != nil {
		return nil, err
	}
	s := &secureConn{connBase: newConnBase(onError), in: in, key: key, sessionID: resp.SessionID,
		serial: o.Serial, keepalive: o.Keepalive, lastRx: -1}
	if s.serial == ([6]byte{}) {
		s.serial = DefaultSerial
	}
	if s.keepalive <= 0 {
		s.keepalive = 50 * time.Second
	}
	if err := s.write(SessionAuthenticateFrame(o.UserID, SessionAuthenticateMAC(o.PasswordHash, o.UserID, pub, resp.ServerPub)), nil); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		fr, err := awaitFrame(ctx, in.recv(), time.Until(deadline), func(f Frame) bool { return f.Service == SvcSecureWrapper })
		if err != nil {
			return nil, fmt.Errorf("knx ip secure: waiting for SESSION_STATUS: %w", err)
		}
		inner, ok := s.unwrap(fr)
		if !ok || inner.Service != SvcSessionStatus || len(inner.Body) < 1 {
			continue
		}
		if inner.Body[0] != SessionAuthSuccess {
			return nil, fmt.Errorf("knx ip secure: user %d not authenticated: %s", o.UserID, sessionStatusText(inner.Body[0]))
		}
		break
	}
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.readLoop() }()
	go func() { defer s.wg.Done(); s.keepaliveLoop() }()
	return s, nil
}

func sessionStatusText(st byte) string {
	switch st {
	case SessionAuthSuccess:
		return "authenticated (0)"
	case SessionAuthFailed:
		return "authentication failed (1)"
	case SessionUnauthenticated:
		return "unauthenticated (2)"
	case SessionTimeout:
		return "session timeout (3)"
	case SessionKeepalive:
		return "keepalive (4)"
	case SessionClose:
		return "session closed (5)"
	}
	return fmt.Sprintf("status %#02x", st)
}

// awaitFrame waits for a frame accepted by match, dropping others.
func awaitFrame(ctx context.Context, ch <-chan rxFrame, wait time.Duration, match func(Frame) bool) (Frame, error) {
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		case <-timer.C:
			return Frame{}, fmt.Errorf("no answer within %s", wait)
		case r, ok := <-ch:
			if !ok {
				return Frame{}, ErrConnectionLost
			}
			if match(r.f) {
				return r.f, nil
			}
		}
	}
}

// unwrap checks and decrypts a wrapper: our session, a sequence number
// above every one accepted before, a valid MAC. Anything else is dropped.
func (s *secureConn) unwrap(fr Frame) (Frame, bool) {
	if fr.Service != SvcSecureWrapper {
		s.report(fmt.Errorf("knx ip secure: plain frame %#04x on a secure session dropped", fr.Service))
		return Frame{}, false
	}
	w, inner, err := ParseSecureWrapper(s.key, fr.Body)
	if err != nil {
		s.report(err)
		return Frame{}, false
	}
	if w.SessionID != s.sessionID {
		s.report(fmt.Errorf("%w: wrapper for session %d on session %d", ErrSecure, w.SessionID, s.sessionID))
		return Frame{}, false
	}
	if int64(w.Seq) <= s.lastRx {
		s.report(fmt.Errorf("%w: sequence %d not above %d (replay?)", ErrSecure, w.Seq, s.lastRx))
		return Frame{}, false
	}
	s.lastRx = int64(w.Seq)
	return inner, true
}

func (s *secureConn) readLoop() {
	for r := range s.in.recv() {
		inner, ok := s.unwrap(r.f)
		if !ok {
			continue
		}
		if inner.Service == SvcSessionStatus && len(inner.Body) >= 1 {
			switch inner.Body[0] {
			case SessionClose, SessionTimeout, SessionUnauthenticated, SessionAuthFailed:
				s.end(fmt.Errorf("%w: the gateway ended the secure session: %s", ErrConnectionLost, sessionStatusText(inner.Body[0])))
				s.in.close()
				return
			}
			continue
		}
		if !s.deliver(rxFrame{f: inner}) {
			s.end(fmt.Errorf("%w: closed", ErrConnectionLost))
			return
		}
	}
	s.end(s.in.err())
}

func (s *secureConn) keepaliveLoop() {
	tick := time.NewTicker(max(s.keepalive/4, 10*time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
		}
		s.wmu.Lock()
		idle := time.Since(s.lastSend)
		s.wmu.Unlock()
		if idle >= s.keepalive {
			_ = s.write(SessionStatusFrame(SessionKeepalive), nil)
		}
	}
}

// write wraps a frame with the next sequence number.
func (s *secureConn) write(f Frame, _ *net.UDPAddr) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.txSeq >= 1<<48 {
		return errors.New("knx ip secure: sequence counter exhausted; the session must be renewed")
	}
	w := SecureWrapper{SessionID: s.sessionID, Seq: s.txSeq, Serial: s.serial, Tag: MessageTagTunnelling}
	s.txSeq++
	s.lastSend = time.Now()
	return s.in.write(w.Wrap(s.key, f), nil)
}

func (s *secureConn) close() {
	s.once.Do(func() {
		_ = s.write(SessionStatusFrame(SessionClose), nil)
		close(s.stop)
	})
	s.in.close()
	s.wg.Wait()
}
