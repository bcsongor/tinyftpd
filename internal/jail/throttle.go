package jail

import (
	"maps"
	"net/netip"
	"sync"
	"time"
)

// After maxFailures failed logins from a network within failureWindow, the
// network's logins fail unchecked until the window ends.
const (
	maxFailures   = 10
	failureWindow = time.Minute
)

// Throttle slows password guessing. The zero value is ready to use.
type Throttle struct {
	mu    sync.Mutex
	m     map[netip.Prefix]failures
	swept time.Time
}

type failures struct {
	n     int
	since time.Time
}

// Check runs auth for a login from remote, a "host:port" address, unless its
// network has failed too often lately. A failure takes a second, which also
// slows guessing over a single connection.
func (t *Throttle) Check(auth Auth, remote, user, password string) (Account, bool) {
	network := Network(remote)
	if t.allow(network) {
		if acct, ok := auth(user, password); ok {
			return acct, true
		}
		t.fail(network)
	}
	time.Sleep(time.Second)
	return Account{}, false
}

func (t *Throttle) allow(network netip.Prefix) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.m[network]
	return f.n < maxFailures || time.Since(f.since) > failureWindow
}

func (t *Throttle) fail(network netip.Prefix) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.swept) > failureWindow {
		maps.DeleteFunc(t.m, func(_ netip.Prefix, f failures) bool { return now.Sub(f.since) > failureWindow })
		t.swept = now
	}
	if t.m == nil {
		t.m = map[netip.Prefix]failures{}
	}
	f := t.m[network]
	if now.Sub(f.since) > failureWindow {
		f = failures{since: now}
	}
	f.n++
	t.m[network] = f
}

// Network returns the network a "host:port" address counts as for limits:
// its IP, or its /64 for IPv6, since one host can use any address in that.
func Network(remote string) netip.Prefix {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return netip.Prefix{}
	}
	ip := ap.Addr().Unmap().WithZone("")
	bits := 32
	if ip.Is6() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p
}
