package ftp

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"net"
	"slices"
	"strings"
	"time"
)

// Explicit FTPS (RFC 4217). With Server.TLS set, clients must upgrade the
// control connection with AUTH TLS before logging in, and switch data
// connections to TLS with PROT P before any listing or transfer.

const handshakeTimeout = 30 * time.Second

func (s *session) auth(arg string) {
	switch {
	case s.srv.TLS == nil:
		s.reply(502, "TLS is not enabled on this server")
	case s.secure:
		s.reply(503, "Already using TLS")
	case !strings.EqualFold(arg, "TLS") && !strings.EqualFold(arg, "TLS-C") && !strings.EqualFold(arg, "SSL"):
		s.reply(504, "Unknown AUTH type, use AUTH TLS")
	default:
		s.reply(234, "AUTH TLS OK.")
		s.sessionTLS()
		c, err := handshake(s.conn, s.tls)
		if err != nil {
			s.log.Warn("TLS handshake failed", "err", err)
			s.conn.Close()
			return
		}
		state := c.ConnectionState()
		s.log.Info("TLS", "version", tls.VersionName(state.Version), "kex", state.CurveID.String())
		if !s.mustResume {
			s.log.Warn("client can't resume TLS sessions, so data connections are only checked by address")
		}
		s.conn, s.in, s.secure = c, bufio.NewScanner(c), true
	}
}

// pbsz accepts PBSZ 0, the only buffer size TLS uses.
func (s *session) pbsz(string) {
	if !s.secure {
		s.reply(503, "Use AUTH TLS first")
		return
	}
	s.reply(200, "PBSZ=0")
}

func (s *session) prot(arg string) {
	switch {
	case !s.secure:
		s.reply(503, "Use AUTH TLS first")
	case strings.EqualFold(arg, "P"):
		s.private = true
		s.reply(200, "Data protection level set to private")
	case strings.EqualFold(arg, "C"):
		s.reply(534, "Data connections must be encrypted, use PROT P")
	default:
		s.reply(504, "Unknown protection level")
	}
}

// PostQuantumKeyExchanges are the hybrid key exchanges that pair a classical
// one with ML-KEM, so sessions stay secret even against a future quantum
// computer while still being as strong as the classical one today.
var PostQuantumKeyExchanges = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}

// postQuantumOnly reports whether cfg allows nothing but post-quantum key
// exchange.
func postQuantumOnly(cfg *tls.Config) bool {
	return cfg != nil && len(cfg.CurvePreferences) > 0 &&
		!slices.ContainsFunc(cfg.CurvePreferences, func(c tls.CurveID) bool { return !slices.Contains(PostQuantumKeyExchanges, c) })
}

// sessionTLS sets up the TLS config for this control connection and its data
// connections, with session tickets that only work here. Data connections
// have to resume the control connection's session, which proves they come
// from the same client: someone else behind the same address can't take
// over a transfer by connecting to the data port first.
//
// That needs the client to resume sessions, which takes TLS 1.3 or session
// tickets: Go doesn't resume TLS 1.2 by session ID. Clients that can't, such
// as curl on TLS 1.2, are only checked by address.
func (s *session) sessionTLS() {
	cfg := s.srv.TLS.Clone()
	var key [32]byte
	rand.Read(key[:])
	cfg.SetSessionTicketKeys([][32]byte{key})
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !s.secure { // the control connection's handshake
			s.mustResume = slices.Contains(hello.SupportedVersions, tls.VersionTLS13) ||
				slices.Contains(hello.Extensions, extSessionTicket)
		}
		return nil, nil
	}
	s.tls = cfg
}

const extSessionTicket = 35 // RFC 5077

// handshake upgrades c to a TLS server connection, giving up after
// handshakeTimeout.
func handshake(c net.Conn, cfg *tls.Config) (*tls.Conn, error) {
	tc := tls.Server(c, cfg)
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	return tc, tc.Handshake()
}
