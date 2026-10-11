// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// KNX IP Secure routing (KNX Standard volume 3 part 8 chapter 9; AN159):
// routers on a secure backbone wrap every frame in a SECURE_WRAPPER with
// session id 0, keyed with the backbone key. The 48-bit sequence field
// carries a shared timer in milliseconds instead of a counter; the routers
// keep it in step with TIMER_NOTIFY frames (timer value, serial, message
// tag and a MAC keyed with the backbone key over block 0 and the frame
// header), and a wrapper whose timer lags more than the latency tolerance
// is discarded. One router, the time keeper, sends a notification about
// every 10 seconds; the others follow, and any of them answers a frame
// with an old timer by sending an update. A newcomer asks with a
// notification of its own and adopts the answer, or becomes the time
// keeper when nobody answers. The event rules below are the public
// description of AN159 as in the MIT-licensed xknx project
// (xknx/io/ip_secure.py, SecureSequenceTimer); no code was taken.

// TimerNotify is a TIMER_NOTIFY frame.
type TimerNotify struct {
	Timer  uint64 // 48 bits, milliseconds
	Serial [6]byte
	Tag    [2]byte
	MAC    []byte
}

const timerNotifyLen = 6 + 6 + 2 + macLen

func (n TimerNotify) blocks() (b0, ctr0 []byte) {
	b := seq48(n.Timer)
	b = append(b, n.Serial[:]...)
	b = append(b, n.Tag[:]...)
	return append(append([]byte(nil), b...), 0, 0), append(b, 0xFF, 0)
}

// Sealed returns the notification with its MAC computed with key.
func (n TimerNotify) Sealed(key []byte) TimerNotify {
	blk := newBlock(key)
	b0, c0 := n.blocks()
	mac := cbcMAC(blk, b0, header(SvcTimerNotify, headerLen+timerNotifyLen), nil)
	n.MAC, _ = ctrXOR(blk, c0, mac, nil)
	return n
}

// Verify checks the notification's MAC with key.
func (n TimerNotify) Verify(key []byte) bool {
	return len(n.MAC) == macLen && CheckMAC(n.Sealed(key).MAC, n.MAC)
}

// Frame is the TIMER_NOTIFY frame.
func (n TimerNotify) Frame() Frame {
	b := seq48(n.Timer)
	b = append(b, n.Serial[:]...)
	b = append(b, n.Tag[:]...)
	return Frame{Service: SvcTimerNotify, Body: append(b, n.MAC...)}
}

// ParseTimerNotify reads a TIMER_NOTIFY body.
func ParseTimerNotify(b []byte) (TimerNotify, error) {
	if len(b) != timerNotifyLen {
		return TimerNotify{}, fmt.Errorf("%w: TIMER_NOTIFY of %d bytes", ErrSecure, len(b))
	}
	n := TimerNotify{Timer: binary.BigEndian.Uint64(append([]byte{0, 0}, b[:6]...)), MAC: append([]byte(nil), b[14:]...)}
	copy(n.Serial[:], b[6:12])
	copy(n.Tag[:], b[12:14])
	return n, nil
}

// secureTimer is one node's view of the backbone's timer.
type secureTimer struct {
	o    SecureRoutingOptions
	send func(Frame) error

	mu          sync.Mutex
	start       time.Time
	offset      int64 // timer = ms since start + offset
	isKeeper    bool
	authed      bool
	schedUpdate bool
	timer       *time.Timer
	waiting     *[2]byte // tag of our synchronisation request
	synced      chan uint64
	stopped     bool

	syncTol                     time.Duration
	keeperPeriodic, followerMin time.Duration
	followerPeriodicMax         time.Duration
	keeperUpdateMax             time.Duration
	followerUpdateMin           time.Duration
	followerUpdateMax           time.Duration
}

const (
	minKeeperPeriodic = 10 * time.Second
	minKeeperUpdate   = 100 * time.Millisecond
)

func newSecureTimer(o SecureRoutingOptions, send func(Frame) error) *secureTimer {
	t := &secureTimer{o: o, send: send, start: time.Now()}
	t.syncTol = o.Latency / 10
	t.keeperPeriodic = minKeeperPeriodic + 3*t.syncTol
	t.followerMin = t.keeperPeriodic + t.syncTol
	t.followerPeriodicMax = t.followerMin + 10*t.syncTol
	t.keeperUpdateMax = minKeeperUpdate + t.syncTol
	t.followerUpdateMin = t.keeperUpdateMax + t.syncTol
	t.followerUpdateMax = t.followerUpdateMin + 10*t.syncTol
	return t
}

func (t *secureTimer) nowLocked() int64 {
	return time.Since(t.start).Milliseconds() + t.offset
}

func (t *secureTimer) keeper() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.isKeeper
}

func randTag() [2]byte {
	var b [2]byte
	_, _ = crand.Read(b[:])
	return b
}

func (t *secureTimer) notify(tag [2]byte, serial [6]byte) {
	t.mu.Lock()
	n := TimerNotify{Timer: uint64(max(0, t.nowLocked())), Serial: serial, Tag: tag}
	t.mu.Unlock()
	_ = t.send(n.Sealed(t.o.BackboneKey).Frame())
}

// synchronise asks for the time and waits for the answer, or becomes the
// time keeper after the longest a follower may take to answer plus twice
// the latency tolerance.
func (t *secureTimer) synchronise() {
	tag := randTag()
	t.mu.Lock()
	t.waiting = &tag
	t.synced = make(chan uint64, 1)
	ch := t.synced
	t.mu.Unlock()
	t.notify(tag, t.o.Serial)
	wait := t.followerUpdateMax + 2*t.o.Latency
	select {
	case v := <-ch:
		t.mu.Lock()
		t.offset = int64(v) - time.Since(t.start).Milliseconds()
		t.mu.Unlock()
	case <-time.After(wait):
		t.mu.Lock()
		t.isKeeper = true
		t.mu.Unlock()
	}
	t.mu.Lock()
	t.waiting, t.authed = nil, true
	t.mu.Unlock()
	t.reschedule(nil)
}

// reschedule arms the notification timer: an update notification for
// (tag, serial) when update is set, else a periodic one.
func (t *secureTimer) reschedule(update *TimerNotify) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rescheduleLocked(update)
}

func (t *secureTimer) rescheduleLocked(update *TimerNotify) {
	if t.stopped {
		return
	}
	if t.timer != nil {
		t.timer.Stop()
	}
	t.schedUpdate = update != nil
	var lo, hi time.Duration
	switch {
	case update != nil && t.isKeeper:
		lo, hi = minKeeperUpdate, t.keeperUpdateMax
	case update != nil:
		lo, hi = t.followerUpdateMin, t.followerUpdateMax
	case t.isKeeper:
		lo, hi = minKeeperPeriodic, t.keeperPeriodic
	default:
		lo, hi = t.followerMin, t.followerPeriodicMax
	}
	d := lo + time.Duration(rand.Int64N(int64(hi-lo)+1))
	var u TimerNotify
	if update != nil {
		u = *update
	}
	isUpdate := update != nil
	t.timer = time.AfterFunc(d, func() {
		if isUpdate {
			t.notify(u.Tag, u.Serial)
		} else {
			t.notify(randTag(), t.o.Serial)
		}
		t.mu.Lock()
		t.isKeeper = true
		t.rescheduleLocked(nil)
		t.mu.Unlock()
	})
}

func (t *secureTimer) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.timer != nil {
		t.timer.Stop()
	}
}

// onNotify handles a TIMER_NOTIFY (AN159 events E1 to E4 and E11).
func (t *secureTimer) onNotify(body []byte) {
	n, err := ParseTimerNotify(body)
	if err != nil || !n.Verify(t.o.BackboneKey) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.waiting != nil && n.Serial == t.o.Serial && n.Tag == *t.waiting {
		select {
		case t.synced <- n.Timer:
		default:
		}
		return
	}
	if n.Serial == t.o.Serial {
		return // our own notification, looped back
	}
	local := t.nowLocked()
	got := int64(n.Timer)
	switch {
	case got > local:
		t.offset += got - local
		t.isKeeper = false
		t.rescheduleLocked(nil)
	case got > local-t.syncTol.Milliseconds():
		t.isKeeper = false
		t.rescheduleLocked(nil)
	case got > local-t.o.Latency.Milliseconds():
	default:
		if !t.schedUpdate {
			t.rescheduleLocked(&n)
		}
	}
}

// unwrap opens a wrapper and checks its timer (events E5 to E8); false
// discards it.
func (t *secureTimer) unwrap(body []byte) (Frame, bool) {
	t.mu.Lock()
	authed := t.authed
	t.mu.Unlock()
	if !authed {
		return Frame{}, false
	}
	w, inner, err := ParseSecureWrapper(t.o.BackboneKey, body)
	if err != nil || w.SessionID != 0 {
		return Frame{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if w.Serial == t.o.Serial {
		return Frame{}, false // our own frame, looped back
	}
	local := t.nowLocked()
	got := int64(w.Seq)
	switch {
	case got > local:
		t.offset += got - local
		if !t.schedUpdate {
			t.rescheduleLocked(nil)
		}
	case got > local-t.syncTol.Milliseconds():
		if !t.schedUpdate {
			t.rescheduleLocked(nil)
		}
	case got > local-t.o.Latency.Milliseconds():
	default:
		if !t.schedUpdate {
			t.rescheduleLocked(&TimerNotify{Serial: w.Serial, Tag: w.Tag})
		}
		return Frame{}, false
	}
	return inner, true
}

// wrap puts a frame in a wrapper stamped with the current timer (event E9).
func (t *secureTimer) wrap(f Frame) Frame {
	t.mu.Lock()
	if !t.schedUpdate {
		t.rescheduleLocked(nil)
	}
	w := SecureWrapper{SessionID: 0, Seq: uint64(max(0, t.nowLocked())), Serial: t.o.Serial, Tag: randTag()}
	t.mu.Unlock()
	return w.Wrap(t.o.BackboneKey, f)
}
