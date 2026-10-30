package ftp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jlaffaye/ftp"

	"tinyftpd/internal/jail"
)

// start runs a server on localhost with users "rw" and "ro" (password "pw")
// jailed to the returned folder, and returns its address. opts adjust the
// server before it starts.
func start(t *testing.T, opts ...func(*Server)) (addr, root string) {
	t.Helper()
	root = t.TempDir()
	srv := &Server{
		Auth: func(user, password string) (jail.Account, bool) {
			if password != "pw" || (user != "rw" && user != "ro") {
				return jail.Account{}, false
			}
			return jail.Account{Root: root, ReadOnly: user == "ro"}, true
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return ln.Addr().String(), root
}

func login(t *testing.T, addr, user string, opts ...ftp.DialOption) *ftp.ServerConn {
	t.Helper()
	c, err := ftp.Dial(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Quit() })
	if err := c.Login(user, "pw"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBanner(t *testing.T) {
	addr, _ := start(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "220---------- Welcome to Tiny-FTPd ----------\r\n") {
		t.Fatalf("unexpected banner:\n%s", buf[:n])
	}
}

func TestBadPassword(t *testing.T) {
	addr, _ := start(t)
	c, err := ftp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Quit()
	if err := c.Login("rw", "nope"); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}
}

func TestFileOperations(t *testing.T) {
	for name, opts := range map[string][]ftp.DialOption{
		"EPSV": nil,
		"PASV": {ftp.DialWithDisabledEPSV(true)},
	} {
		t.Run(name, func(t *testing.T) {
			addr, root := start(t)
			c := login(t, addr, "rw", opts...)
			data := bytes.Repeat([]byte("tinyftpd"), 300_000)

			must(t, c.MakeDir("docs"))
			must(t, c.ChangeDir("docs"))
			must(t, c.Stor("a.bin", bytes.NewReader(data)))
			must(t, c.Rename("a.bin", "b.bin"))

			got, err := os.ReadFile(filepath.Join(root, "docs", "b.bin"))
			must(t, err)
			if !bytes.Equal(got, data) {
				t.Fatal("uploaded file differs")
			}

			entries, err := c.List("")
			must(t, err)
			if len(entries) != 1 || entries[0].Name != "b.bin" || entries[0].Size != uint64(len(data)) {
				t.Fatalf("unexpected listing: %+v", entries)
			}

			// Resume a download from an offset.
			r, err := c.RetrFrom("b.bin", 1000)
			must(t, err)
			got, err = io.ReadAll(r)
			r.Close()
			must(t, err)
			if !bytes.Equal(got, data[1000:]) {
				t.Fatal("resumed download differs")
			}

			must(t, c.Delete("b.bin"))
			must(t, c.ChangeDirToParent())
			must(t, c.RemoveDir("docs"))
		})
	}
}

func TestConcurrentTransfers(t *testing.T) {
	addr, root := start(t)
	// The group returns once all its parallel subtests finish.
	t.Run("group", func(t *testing.T) {
		for i := range 8 {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()
				data := make([]byte, 4<<20)
				mrand.NewChaCha8([32]byte{byte(i)}).Read(data)
				name := fmt.Sprintf("file-%d.bin", i)

				c := login(t, addr, "rw")
				must(t, c.Stor(name, bytes.NewReader(data)))
				r, err := c.Retr(name)
				must(t, err)
				got, err := io.ReadAll(r)
				r.Close()
				must(t, err)
				if !bytes.Equal(got, data) {
					t.Fatal("downloaded file differs")
				}
			})
		}
	})

	entries, err := os.ReadDir(root)
	must(t, err)
	if len(entries) != 8 {
		t.Fatalf("got %d files, want 8", len(entries))
	}
}

func TestStartFolder(t *testing.T) {
	startIn := func(dir string) func(*Server) {
		return func(s *Server) {
			auth := s.Auth
			s.Auth = func(user, password string) (jail.Account, bool) {
				acct, ok := auth(user, password)
				acct.Start = dir
				return acct, ok
			}
		}
	}
	addr, root := start(t, startIn("/photos/2026"))
	must(t, os.MkdirAll(filepath.Join(root, "photos", "2026"), 0o755))

	c := login(t, addr, "rw")
	if dir, _ := c.CurrentDir(); dir != "/photos/2026" {
		t.Fatalf("started in %q", dir)
	}
	// Still jailed to the root, not the start folder.
	must(t, c.ChangeDir("/"))

	// A start folder that's gone falls back to the root.
	addr, _ = start(t, startIn("/missing"))
	if dir, _ := login(t, addr, "rw").CurrentDir(); dir != "/" {
		t.Fatalf("started in %q, want /", dir)
	}
}

func TestJail(t *testing.T) {
	addr, root := start(t)
	outside := filepath.Join(filepath.Dir(root), "secret.txt")
	must(t, os.WriteFile(outside, []byte("secret"), 0o644))
	t.Cleanup(func() { os.Remove(outside) })

	c := login(t, addr, "rw")
	must(t, c.ChangeDir("../../.."))
	if dir, _ := c.CurrentDir(); dir != "/" {
		t.Fatalf("escaped to %q", dir)
	}
	if _, err := c.Retr("../secret.txt"); err == nil {
		t.Fatal("read a file outside the root")
	}

	if runtime.GOOS != "windows" { // symlinks need admin rights on Windows
		must(t, os.Symlink(outside, filepath.Join(root, "link")))
		if _, err := c.Retr("link"); err == nil {
			t.Fatal("followed a symlink outside the root")
		}
	}
}

func TestFailedUploadKeepsFile(t *testing.T) {
	addr, root := start(t)
	path := filepath.Join(root, "keep.txt")
	must(t, os.WriteFile(path, []byte("precious"), 0o644))

	expect(t, rawLogin(t, addr, "rw"), "STOR keep.txt", 425) // no PASV, so no data connection
	if got, _ := os.ReadFile(path); string(got) != "precious" {
		t.Fatalf("file changed to %q", got)
	}
}

func TestRestPastEnd(t *testing.T) {
	addr, root := start(t)
	path := filepath.Join(root, "small.txt")
	must(t, os.WriteFile(path, []byte("hi"), 0o644))

	c := login(t, addr, "rw")
	if err := c.StorFrom("small.txt", strings.NewReader(""), 1<<40); err == nil {
		t.Error("restarted an upload past the end of the file")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 2 {
		t.Fatalf("file changed: %v, %v", fi.Size(), err)
	}
}

func TestDataFromOtherAddress(t *testing.T) {
	addr, root := start(t)
	must(t, os.WriteFile(filepath.Join(root, "f.txt"), []byte("hi"), 0o644))
	c := rawLogin(t, addr, "rw")
	msg := expect(t, c, "EPSV", 229)
	port := msg[strings.Index(msg, "|||")+3 : strings.LastIndex(msg, "|")]
	data := net.JoinHostPort("127.0.0.1", port)

	// A stranger connecting first must not hijack or abort the transfer.
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	stranger, err := d.Dial("tcp", data)
	if err != nil {
		t.Skip("can't connect from 127.0.0.2:", err)
	}
	defer stranger.Close()
	conn, err := net.Dial("tcp", data)
	must(t, err)
	defer conn.Close()

	must(t, c.PrintfLine("RETR f.txt"))
	_, _, err = c.ReadResponse(150)
	must(t, err)
	got, err := io.ReadAll(conn)
	must(t, err)
	if _, _, err := c.ReadResponse(226); err != nil || string(got) != "hi" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestUserAfterLogin(t *testing.T) {
	addr, _ := start(t)
	c := rawLogin(t, addr, "ro")
	expect(t, c, "USER rw", 503) // would restart the login without its time limit
}

func TestReadOnly(t *testing.T) {
	addr, root := start(t)
	must(t, os.WriteFile(filepath.Join(root, "keep.txt"), []byte("hi"), 0o644))

	c := login(t, addr, "ro")
	if err := c.Stor("new.txt", strings.NewReader("x")); err == nil {
		t.Error("read-only user uploaded a file")
	}
	if err := c.Delete("keep.txt"); err == nil {
		t.Error("read-only user deleted a file")
	}
	r, err := c.Retr("keep.txt")
	must(t, err)
	r.Close()
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows inherits ACLs instead of Unix permission bits")
	}
	addr, root := start(t)
	// Group write would normally be stripped by a 022 umask, and setgid keeps
	// shared-group folders working.
	must(t, os.Chmod(root, os.ModeSetgid|0o770))
	mode := func(name string) os.FileMode {
		fi, err := os.Stat(filepath.Join(root, name))
		must(t, err)
		return fi.Mode().Perm()
	}

	c := login(t, addr, "rw")
	must(t, c.MakeDir("shared"))
	must(t, c.Stor("file", strings.NewReader("x")))
	if got := mode("shared"); got != 0o770 {
		t.Errorf("new directory has mode %o, want 770", got)
	}
	if fi, _ := os.Stat(filepath.Join(root, "shared")); fi.Mode()&os.ModeSetgid == 0 {
		t.Error("new directory lost setgid")
	}
	if got := mode("file"); got != 0o660 {
		t.Errorf("new file has mode %o, want 660", got)
	}

	// A locked-down subfolder keeps new files private.
	must(t, os.Mkdir(filepath.Join(root, "private"), 0o700))
	must(t, c.Stor("private/secret", strings.NewReader("x")))
	if got := mode("private/secret"); got != 0o600 {
		t.Errorf("file in a 700 folder has mode %o, want 600", got)
	}

	rw, ro := rawLogin(t, addr, "rw"), rawLogin(t, addr, "ro")
	expect(t, rw, "SITE CHMOD 640 file", 200)
	if got := mode("file"); got != 0o640 {
		t.Errorf("chmodded file has mode %o, want 640", got)
	}
	expect(t, ro, "SITE CHMOD 777 file", 550)
	expect(t, rw, "SITE CHMOD 4755 file", 501) // no setuid
}

func TestTimestamps(t *testing.T) {
	addr, root := start(t)
	c := login(t, addr, "rw")
	must(t, c.Stor("f.txt", strings.NewReader("x")))

	want := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	must(t, c.SetTime("f.txt", want)) // MFMT
	if fi, err := os.Stat(filepath.Join(root, "f.txt")); err != nil || !fi.ModTime().Equal(want) {
		t.Fatalf("file time is %v, want %v", fi.ModTime(), want)
	}

	entries, err := c.List("") // MLSD, since FEAT advertises MLST
	must(t, err)
	if len(entries) != 1 || !entries[0].Time.Equal(want) {
		t.Fatalf("listing: %+v, want time %v", entries, want)
	}

	raw := rawLogin(t, addr, "ro")
	if got := expect(t, raw, "MLST f.txt", 250); !strings.Contains(got, "type=file;size=1;modify=20010203040506;perm=r;") {
		t.Errorf("MLST for a read-only user: %q", got)
	}
	expect(t, raw, "MFMT 20200101000000 f.txt", 550)
}

func TestChecksums(t *testing.T) {
	addr, root := start(t)
	data := []byte("Welcome to Tiny-FTPd")
	must(t, os.WriteFile(filepath.Join(root, "f.txt"), data, 0o644))
	md5sum, sha1sum, sha256sum, sha512sum := md5.Sum(data), sha1.Sum(data), sha256.Sum256(data), sha512.Sum512(data)

	c := rawLogin(t, addr, "ro") // read-only users can verify downloads
	for cmd, want := range map[string]string{
		"XCRC f.txt":    fmt.Sprintf("%08x", crc32.ChecksumIEEE(data)),
		"XMD5 f.txt":    hex.EncodeToString(md5sum[:]),
		"XSHA1 f.txt":   hex.EncodeToString(sha1sum[:]),
		"XSHA256 f.txt": hex.EncodeToString(sha256sum[:]),
		"XSHA512 f.txt": hex.EncodeToString(sha512sum[:]),
	} {
		if got := expect(t, c, cmd, 250); got != want {
			t.Errorf("%s = %s, want %s", cmd, got, want)
		}
	}

	if got, want := expect(t, c, "HASH f.txt", 213), "SHA-256 0-20 "+hex.EncodeToString(sha256sum[:])+" f.txt"; got != want {
		t.Errorf("HASH = %q, want %q", got, want)
	}
	expect(t, c, "OPTS HASH md5", 200)
	if got := expect(t, c, "HASH f.txt", 213); !strings.HasPrefix(got, "MD5 0-20 "+hex.EncodeToString(md5sum[:])) {
		t.Errorf("HASH after OPTS HASH MD5 = %q", got)
	}
	expect(t, c, "OPTS HASH whirlpool", 501)
}

func TestAVBL(t *testing.T) {
	addr, _ := start(t)
	c := rawLogin(t, addr, "rw")
	if !strings.Contains(expect(t, c, "FEAT", 211), "AVBL") {
		t.Error("FEAT doesn't list AVBL")
	}
	if n, err := strconv.ParseUint(expect(t, c, "AVBL", 213), 10, 64); err != nil || n == 0 {
		t.Errorf("AVBL = %d, %v", n, err)
	}
	expect(t, c, "AVBL /missing", 550)
}

func TestTLS(t *testing.T) {
	serverTLS, clientTLS := testCerts(t)
	addr, root := start(t, func(s *Server) { s.TLS = serverTLS })

	// Plain logins are refused, so passwords never cross the network in clear.
	plain, err := ftp.Dial(addr)
	must(t, err)
	defer plain.Quit()
	if err := plain.Login("rw", "pw"); err == nil {
		t.Fatal("logged in without TLS")
	}

	// A TLS client works end to end, data connections included.
	c := login(t, addr, "rw", ftp.DialWithExplicitTLS(clientTLS))
	data := bytes.Repeat([]byte("secret "), 100_000)
	must(t, c.Stor("f.bin", bytes.NewReader(data)))
	r, err := c.Retr("f.bin")
	must(t, err)
	got, err := io.ReadAll(r)
	r.Close()
	must(t, err)
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded file differs")
	}
	if got, _ := os.ReadFile(filepath.Join(root, "f.bin")); !bytes.Equal(got, data) {
		t.Fatal("uploaded file differs")
	}

	// Data connections must be encrypted too.
	conn, err := net.Dial("tcp", addr)
	must(t, err)
	defer conn.Close()
	tp := textproto.NewConn(conn)
	_, banner, err := tp.ReadResponse(220)
	must(t, err)
	if !strings.Contains(banner, "Only secure TLS connections are accepted") {
		t.Errorf("banner doesn't mention TLS:\n%s", banner)
	}
	expect(t, tp, "AUTH TLS", 234)
	tc := tls.Client(conn, clientTLS)
	must(t, tc.Handshake())
	tp = textproto.NewConn(tc)
	expect(t, tp, "USER rw", 331)
	expect(t, tp, "PASS pw", 230)
	expect(t, tp, "PROT C", 534)
	expect(t, tp, "EPSV", 229)
	expect(t, tp, "LIST", 521)
}

// Data connections must resume their own control connection's TLS session,
// so nobody else at the client's address can take over a transfer.
func TestDataSessionReuse(t *testing.T) {
	serverTLS, clientTLS := testCerts(t)
	addr, root := start(t, func(s *Server) { s.TLS = serverTLS })
	stored := func(c *ftp.ServerConn) bool {
		c.Stor("f.txt", strings.NewReader("x"))
		got, _ := os.ReadFile(filepath.Join(root, "f.txt"))
		os.Remove(filepath.Join(root, "f.txt"))
		return string(got) == "x"
	}

	noReuse := clientTLS.Clone()
	noReuse.ClientSessionCache = nil
	if stored(login(t, addr, "rw", ftp.DialWithExplicitTLS(noReuse))) {
		t.Error("transferred without resuming the session")
	}

	// The shared cache ends up with b's session, which a can't use.
	shared := clientTLS.Clone()
	shared.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	a := login(t, addr, "rw", ftp.DialWithExplicitTLS(shared))
	login(t, addr, "rw", ftp.DialWithExplicitTLS(shared))
	if stored(a) {
		t.Error("transferred with another connection's session")
	}

	// TLS 1.2 without session tickets can't resume at all, so such clients
	// are only checked by address.
	old := noReuse.Clone()
	old.MaxVersion, old.SessionTicketsDisabled = tls.VersionTLS12, true
	if !stored(login(t, addr, "rw", ftp.DialWithExplicitTLS(old))) {
		t.Error("a TLS 1.2 client without session tickets can't transfer")
	}
}

func TestPostQuantumTLS(t *testing.T) {
	serverTLS, clientTLS := testCerts(t)
	serverTLS.MinVersion, serverTLS.CurvePreferences = tls.VersionTLS13, PostQuantumKeyExchanges
	addr, _ := start(t, func(s *Server) { s.TLS = serverTLS })

	// handshake upgrades a fresh control connection and returns the result.
	handshake := func(cfg *tls.Config) (tls.ConnectionState, string, error) {
		conn, err := net.Dial("tcp", addr)
		must(t, err)
		defer conn.Close()
		tp := textproto.NewConn(conn)
		_, banner, err := tp.ReadResponse(220)
		must(t, err)
		expect(t, tp, "AUTH TLS", 234)
		tc := tls.Client(conn, cfg)
		err = tc.Handshake()
		return tc.ConnectionState(), banner, err
	}

	state, banner, err := handshake(clientTLS) // Go offers X25519MLKEM768 by default
	must(t, err)
	if state.CurveID != tls.X25519MLKEM768 {
		t.Errorf("negotiated %v, want X25519MLKEM768", state.CurveID)
	}
	if !strings.Contains(banner, "Only post-quantum secure TLS connections") {
		t.Errorf("banner doesn't mention post-quantum:\n%s", banner)
	}

	classical := clientTLS.Clone()
	classical.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	if _, _, err := handshake(classical); err == nil {
		t.Error("a client without post-quantum key exchange got in")
	}
}

func TestConnectionCap(t *testing.T) {
	addr, _ := start(t, func(s *Server) {
		s.MaxConns = 1
		auth := s.Auth
		s.Auth = func(user, password string) (jail.Account, bool) {
			if user == "boss" {
				user = "rw"
				acct, ok := auth(user, password)
				acct.BypassLimit = true
				return acct, ok
			}
			return auth(user, password)
		}
	})

	first := rawLogin(t, addr, "rw")
	if banner := connect(t, addr); !strings.Contains(banner, "You are user number 2 of 1 allowed.") {
		t.Errorf("banner:\n%s", banner)
	}

	// The server is full: a normal user is turned away at login...
	c, err := textproto.Dial("tcp", addr)
	must(t, err)
	defer c.Close()
	_, _, err = c.ReadResponse(220)
	must(t, err)
	expect(t, c, "USER ro", 331)
	expect(t, c, "PASS pw", 421)

	// ...but the boss gets in, without taking the place.
	rawLogin(t, addr, "boss")

	// A place frees up once someone logs out.
	expect(t, first, "QUIT", 221)
	for deadline := time.Now().Add(2 * time.Second); ; {
		c, err := textproto.Dial("tcp", addr)
		must(t, err)
		_, _, err = c.ReadResponse(220)
		must(t, err)
		expect(t, c, "USER ro", 331)
		must(t, c.PrintfLine("PASS pw"))
		code, _, _ := c.ReadResponse(0)
		c.Close()
		if code == 230 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("place never freed up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLoginTimeout(t *testing.T) {
	old := loginTimeout
	loginTimeout = 200 * time.Millisecond
	t.Cleanup(func() { loginTimeout = old })
	addr, _ := start(t)

	conn, err := net.Dial("tcp", addr)
	must(t, err)
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("idle connection wasn't dropped: %v", err)
	}

	// Logged-in sessions aren't affected.
	c := rawLogin(t, addr, "rw")
	time.Sleep(400 * time.Millisecond)
	expect(t, c, "NOOP", 200)
}

func TestPendingLimit(t *testing.T) {
	old := maxPending
	maxPending = 2
	t.Cleanup(func() { maxPending = old })
	addr, _ := start(t)

	dial := func(want int) *textproto.Conn {
		t.Helper()
		c, err := textproto.Dial("tcp", addr)
		must(t, err)
		t.Cleanup(func() { c.Close() })
		_, _, err = c.ReadResponse(want)
		must(t, err)
		return c
	}
	first := dial(220)
	dial(220)
	dial(421) // a third connection from the same IP waiting to log in

	// Logging in frees a place.
	expect(t, first, "USER rw", 331)
	expect(t, first, "PASS pw", 230)
	dial(220)
}

// connect reads the banner of a fresh connection.
func connect(t *testing.T, addr string) string {
	t.Helper()
	c, err := textproto.Dial("tcp", addr)
	must(t, err)
	defer c.Close()
	_, banner, err := c.ReadResponse(220)
	must(t, err)
	return banner
}

// testCerts returns a server TLS config with a certificate for 127.0.0.1
// from a throwaway CA, and a client config that trusts that CA.
func testCerts(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(t, err)
		return k
	}
	caKey, leafKey := key(), key()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Tiny-FTPd test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(t, err)
	ca, err = x509.ParseCertificate(caDER)
	must(t, err)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	must(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	// The session cache lets data connections resume the control
	// connection's TLS session, which the server requires.
	return server, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", ClientSessionCache: tls.NewLRUClientSessionCache(0)}
}

// rawLogin logs in as user over a plain control connection, for commands the
// client library doesn't cover.
func rawLogin(t *testing.T, addr, user string) *textproto.Conn {
	t.Helper()
	c, err := textproto.Dial("tcp", addr)
	must(t, err)
	t.Cleanup(func() { c.Close() })
	_, _, err = c.ReadResponse(220)
	must(t, err)
	expect(t, c, "USER "+user, 331)
	expect(t, c, "PASS pw", 230)
	return c
}

// expect sends cmd and checks the reply code, returning the reply text.
func expect(t *testing.T, c *textproto.Conn, cmd string, want int) string {
	t.Helper()
	must(t, c.PrintfLine("%s", cmd))
	_, msg, err := c.ReadResponse(want)
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return msg
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
