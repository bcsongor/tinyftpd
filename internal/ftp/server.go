// Package ftp is a small FTP server with passive-mode transfers and users
// jailed to their own folders.
package ftp

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tinyftpd/internal/jail"
)

// Server is an FTP server. Auth is required; other fields are optional.
type Server struct {
	// Auth checks credentials. It runs on every login, so user changes apply
	// without a restart.
	Auth jail.Auth
	// PasvMin and PasvMax bound the passive data ports. Zero lets the OS pick.
	PasvMin, PasvMax int
	// PublicIP is advertised in PASV replies instead of the local address,
	// for servers behind NAT.
	PublicIP string
	// TLS, when set, makes explicit FTPS mandatory: clients must send AUTH TLS
	// before logging in and PROT P before any data transfer.
	TLS *tls.Config
	// MaxConns caps how many users can be logged in at once; users with
	// Account.BypassLimit don't count and always get in. Zero means no limit.
	MaxConns int
	// Logger defaults to slog.Default().
	Logger *slog.Logger

	loggedIn atomic.Int64  // users counting towards MaxConns
	waiting  netCounts     // connections yet to log in
	throttle jail.Throttle // slows password guessing
}

// Serve accepts connections on ln until ctx is cancelled, then closes all
// sessions and returns nil.
func (srv *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx, func() { ln.Close() })

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { srv.handle(ctx, conn) })
	}
}

// The connection limit only applies once we know who's logging in. Until
// then, a connection has loginTimeout to log in, and each network can have
// maxPending connections waiting to, so they can't pile up. Once logged in,
// a session or transfer that sits idle for idleTimeout is closed, so idle
// users can't keep others out.
var (
	loginTimeout = 30 * time.Second
	maxPending   = 10
	idleTimeout  = 5 * time.Minute
)

// netCounts counts connections per network, as from jail.Network.
type netCounts struct {
	mu sync.Mutex
	m  map[netip.Prefix]int
}

// add counts one more for network, unless it's already at limit.
func (c *netCounts) add(network netip.Prefix, limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[network] >= limit {
		return false
	}
	if c.m == nil {
		c.m = map[netip.Prefix]int{}
	}
	c.m[network]++
	return true
}

func (c *netCounts) done(network netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[network]--; c.m[network] <= 0 {
		delete(c.m, network)
	}
}

func (srv *Server) logger() *slog.Logger { return cmp.Or(srv.Logger, slog.Default()) }

// handle serves one connection.
func (srv *Server) handle(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	log := srv.logger().With("remote", conn.RemoteAddr().String())
	network := jail.Network(conn.RemoteAddr().String())
	if !srv.waiting.add(network, maxPending) {
		log.Warn("refused, too many connections waiting to log in")
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		io.WriteString(conn, "421 Too many connections from your IP address\r\n")
		conn.Close()
		return
	}
	// Closing the connection, rather than a read deadline, also stops a
	// client that sends commands but never reads the replies.
	timer := time.AfterFunc(loginTimeout, func() {
		log.Warn("didn't log in in time")
		conn.Close()
	})
	s := &session{srv: srv, ctx: ctx, conn: conn, dir: "/", hashAlgo: "SHA-256", log: log}
	s.loginDone = sync.OnceFunc(func() {
		timer.Stop()
		srv.waiting.done(network)
	})
	defer s.loginDone()
	defer s.close()

	s.log.Info("connected")
	s.greet()
	// AUTH TLS swaps s.in for a scanner over the TLS connection.
	s.in = bufio.NewScanner(conn)
	for {
		s.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		if !s.in.Scan() {
			return
		}
		cmd, arg, _ := strings.Cut(s.in.Text(), " ")
		s.exec(strings.ToUpper(cmd), arg)
	}
}

type session struct {
	srv  *Server
	ctx  context.Context
	conn net.Conn       // the control connection, TLS after AUTH TLS
	in   *bufio.Scanner // reads commands from conn
	log  *slog.Logger

	secure bool        // control connection upgraded with AUTH TLS
	tls    *tls.Config // this session's, for its data connections
	// mustResume: data connections must resume the control connection's
	// TLS session. Set for clients that can.
	mustResume bool
	private    bool // PROT P: data connections use TLS

	counted   bool   // counts towards MaxConns
	loginDone func() // stops the login timer; call once logged in

	username string           // from USER, awaiting PASS
	root     *os.Root         // the user's folder; nil until logged in
	readOnly bool             // refuse commands that modify files
	dir      string           // current directory, absolute within root
	data     *net.TCPListener // passive listener for the next transfer
	offset   int64            // from REST, applies to the next RETR or STOR
	renaming string           // from RNFR, applies to the next RNTO
	hashAlgo string           // for HASH, chosen with OPTS HASH
	up, down int64            // bytes transferred, for the goodbye message
}

func (s *session) exec(cmd, arg string) {
	c, ok := commands[cmd]
	switch {
	case !ok:
		s.reply(500, "Unknown command")
	case c.login && s.root == nil:
		s.reply(530, "You aren't logged in")
	case c.write && s.readOnly:
		s.reply(550, "Permission denied")
	default:
		c.fn(s, arg)
	}
	// REST holds until the next transfer, since clients may send PASV in
	// between. RNFR only applies to the command right after it.
	if cmd == "RETR" || cmd == "STOR" {
		s.offset = 0
	}
	if cmd != "RNFR" {
		s.renaming = ""
	}
}

func (s *session) close() {
	s.logout()
	if s.data != nil {
		s.data.Close()
	}
	s.conn.Close()
	s.log.Info("disconnected")
}

func (s *session) logout() {
	if s.root != nil {
		s.root.Close()
		s.root = nil
	}
	if s.counted {
		s.srv.loggedIn.Add(-1)
		s.counted = false
	}
}

// greet sends the welcome banner, in the style of Pure-FTPd.
func (s *session) greet() {
	port := s.conn.LocalAddr().(*net.TCPAddr).Port
	lines := []string{"--------- Welcome to Tiny-FTPd ----------"}
	if s.srv.MaxConns > 0 {
		lines = append(lines, fmt.Sprintf("You are user number %d of %d allowed.", s.srv.loggedIn.Load()+1, s.srv.MaxConns))
	}
	lines = append(lines,
		fmt.Sprintf("Local time is now %s. Server port: %d.", time.Now().Format("15:04"), port),
		"This is a private system - No anonymous login",
	)
	switch {
	case postQuantumOnly(s.srv.TLS):
		lines = append(lines, "Only post-quantum secure TLS connections are accepted on this server.")
	case s.srv.TLS != nil:
		lines = append(lines, "Only secure TLS connections are accepted on this server.")
	}
	s.replyLines(220, append(lines, "IPv6 connections are also welcome on this server.")...)
}

func (s *session) reply(code int, format string, args ...any) {
	s.write(fmt.Sprintf("%d %s\r\n", code, fmt.Sprintf(format, args...)))
}

// write sends a reply, giving up after idleTimeout if the client isn't
// reading.
func (s *session) write(reply string) {
	s.conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	io.WriteString(s.conn, reply)
}

// replyLines sends a multi-line reply: "code-" on every line but the last,
// which gets "code ". Lines starting with a space go out as they are, as FEAT
// and MLST require.
func (s *session) replyLines(code int, lines ...string) {
	var b strings.Builder
	for i, line := range lines {
		switch {
		case i == len(lines)-1:
			fmt.Fprintf(&b, "%d %s\r\n", code, line)
		case strings.HasPrefix(line, " "):
			fmt.Fprintf(&b, "%s\r\n", line)
		default:
			fmt.Fprintf(&b, "%d-%s\r\n", code, line)
		}
	}
	s.write(b.String())
}

// fail reports a filesystem error on name, the path the client sent, without
// the host path.
func (s *session) fail(name string, err error) { s.reply(550, "%s: %s", name, jail.Reason(err)) }

// logged logs a change to the jail and passes err through: info when it
// worked, a warning with the reason when it didn't.
func (s *session) logged(err error, msg string, args ...any) error {
	if err != nil {
		s.log.Warn(msg, append(args, "err", jail.Reason(err))...)
	} else {
		s.log.Info(msg, args...)
	}
	return err
}

// resolve maps a client path to an absolute jail path and its
// os.Root-relative form.
func (s *session) resolve(p string) (abs, rel string) { return jail.Resolve(s.dir, p) }

// listen opens the passive listener for the next transfer and returns its port.
func (s *session) listen() (int, bool) {
	if s.data != nil {
		s.data.Close()
		s.data = nil
	}
	ln, err := s.srv.listenPasv(s.conn.LocalAddr().(*net.TCPAddr).IP)
	if err != nil {
		s.log.Warn("passive listen failed", "err", err)
		s.reply(425, "Can't open data connection")
		return 0, false
	}
	s.data = ln
	return ln.Addr().(*net.TCPAddr).Port, true
}

func (srv *Server) listenPasv(ip net.IP) (*net.TCPListener, error) {
	lo, hi := srv.PasvMin, srv.PasvMax
	if lo <= 0 || hi < lo {
		return net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
	}
	// Start at a random port so concurrent sessions don't all race for the first.
	n := hi - lo + 1
	start := rand.IntN(n)
	for i := range n {
		if ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: lo + (start+i)%n}); err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("no free port in %d-%d", lo, hi)
}

// dataReady checks a transfer can go ahead, replying with why not if it can't.
func (s *session) dataReady() bool {
	switch {
	case s.srv.TLS != nil && !s.private:
		s.reply(521, "Data connections must be encrypted, use PROT P")
	case s.data == nil:
		s.reply(425, "No data connection")
	default:
		return true
	}
	return false
}

// transfer runs fn over the passive data connection. It sends the 150 reply
// and any failure reply, with fn's error stripped of host paths; on success
// the caller sends the 226.
func (s *session) transfer(fn func(net.Conn) (int64, error)) (int64, bool) {
	if !s.dataReady() {
		return 0, false
	}
	ln := s.data
	s.data = nil
	defer ln.Close()

	s.reply(150, "Accepted data connection")
	stopListen := context.AfterFunc(s.ctx, func() { ln.Close() })
	defer stopListen()
	ln.SetDeadline(time.Now().Add(30 * time.Second))
	tcp, err := s.acceptData(ln)
	if err != nil {
		s.reply(425, "Can't open data connection")
		return 0, false
	}
	var c net.Conn = idleConn{tcp}
	defer func() { c.Close() }() // after the upgrade, sends TLS close_notify too
	stop := context.AfterFunc(s.ctx, func() { tcp.Close() })
	defer stop()
	if s.private {
		tc, err := handshake(tcp, s.tls)
		c = idleConn{tc}
		if err != nil {
			s.log.Warn("data TLS handshake failed", "err", err)
			s.reply(425, "TLS handshake failed")
			return 0, false
		}
		if s.mustResume && !tc.ConnectionState().DidResume {
			s.log.Warn("data connection didn't reuse the TLS session, refused")
			s.reply(522, "Data connections must reuse the TLS session of the control connection")
			return 0, false
		}
	}

	n, err := fn(c)
	if err != nil {
		s.log.Warn("transfer failed", "err", jail.Reason(err))
		s.reply(426, "Transfer aborted: %s", jail.Reason(err))
		return n, false
	}
	return n, true
}

// acceptData accepts the data connection from the client on the control
// connection, closing any from other addresses, so they can't hijack or
// abort the transfer.
func (s *session) acceptData(ln *net.TCPListener) (*net.TCPConn, error) {
	client := s.conn.RemoteAddr().(*net.TCPAddr).IP
	for {
		tcp, err := ln.AcceptTCP()
		if err != nil {
			return nil, err
		}
		from := tcp.RemoteAddr().(*net.TCPAddr).IP
		if from.Equal(client) {
			return tcp, nil
		}
		s.log.Warn("data connection from a different address, refused", "from", from.String())
		tcp.Close()
	}
}

// idleConn closes a data connection that makes no progress for idleTimeout.
// Hiding *net.TCPConn costs sendfile, but a deadline for the whole transfer
// would cut off large files.
type idleConn struct{ net.Conn }

func (c idleConn) Read(p []byte) (int, error) {
	c.SetDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Read(p)
}

func (c idleConn) Write(p []byte) (int, error) {
	c.SetDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Write(p)
}

// transferred sends the 226 for a file transfer, with Pure-FTPd's stats line.
func (s *session) transferred(n int64, d time.Duration) {
	secs := max(d.Seconds(), 0.001)
	s.replyLines(226,
		"File successfully transferred",
		fmt.Sprintf("%.3f seconds (measured here), %.2f Mbytes per second", secs, float64(n)/secs/(1<<20)),
	)
}
