// Command tinyftpd is a tiny FTP server with a Win32 GUI for managing users.
package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"tinyftpd/internal/ftp"
	"tinyftpd/internal/jail"
	"tinyftpd/internal/web"
)

const usage = `Tiny-FTPd, a tiny FTP server

Usage:
  tinyftpd [-config file] serve
  tinyftpd [-config file] user add [-readonly] [-bypass-limit] [-start folder] <name> <folder>
  tinyftpd [-config file] user rm <name>
  tinyftpd [-config file] user list
  tinyftpd [-config file] tls self-signed

With no command, Tiny-FTPd opens the GUI on Windows. The config defaults to
tinyftpd.json next to the binary. "user add" updates the user if it exists.
"tls self-signed" creates a certificate next to the config and turns TLS on.
`

func main() {
	configPath := flag.String("config", defaultConfigPath(), "config file")
	flag.Usage = func() { fmt.Fprint(flag.CommandLine.Output(), usage) }
	flag.Parse()

	switch err := run(*configPath, flag.Args()); {
	case errors.Is(err, errUsage):
		flag.Usage()
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "tinyftpd:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(path string, args []string) error {
	if len(args) == 0 {
		if runtime.GOOS == "windows" {
			return runGUI(path)
		}
		return errUsage
	}
	switch args[0] {
	case "serve":
		return serve(path)
	case "user":
		return userCmd(path, args[1:])
	case "tls":
		if len(args) == 2 && args[1] == "self-signed" {
			return selfSignCmd(path)
		}
	}
	return errUsage
}

// fileAuth checks logins against the config file at path, re-reading it
// every time so user changes apply without a restart.
func fileAuth(path string) jail.Auth {
	return func(name, password string) (jail.Account, bool) {
		cfg, err := loadConfig(path)
		if err != nil {
			slog.Error("can't read config", "err", err)
			return jail.Account{}, false
		}
		u, ok := cfg.authenticate(name, password)
		return jail.Account{Root: u.Root, Start: u.Start, ReadOnly: u.ReadOnly, BypassLimit: u.Bypass}, ok
	}
}

func serve(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	wait, err := start(ctx, path, cfg)
	if err != nil {
		return err
	}
	slog.Info("Tiny-FTPd is running on "+cfg.addresses(), "config", path)
	if len(cfg.Users) == 0 {
		slog.Warn("no users yet, add one with: tinyftpd user add <name> <folder>")
	}
	if os.Geteuid() == 0 {
		slog.Warn("running as root, so a bug in Tiny-FTPd could expose the whole system; see the README for serving on port 21 without root")
	}
	return wait()
}

// start checks cfg, opens the FTP listener, and the web one when it's on,
// then serves both until ctx is done. Listening first means a port in use fails here
// rather than later. wait blocks until both servers have stopped.
func start(ctx context.Context, path string, cfg Config) (wait func() error, err error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	tlsConfig, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		leaf := tlsConfig.Certificates[0].Leaf
		slog.Info("TLS certificate", "subject", leaf.Subject.String(), "expires", leaf.NotAfter.Format(time.DateOnly), "sha256", certFingerprint(leaf.Raw))
		checkExpiry(leaf)
	} else {
		slog.Warn("TLS is off, so passwords and files cross the network unencrypted")
	}
	ftpLn, err := net.Listen("tcp", cfg.listenAddr())
	if err != nil {
		return nil, err
	}
	var webLn net.Listener
	if cfg.Web {
		if webLn, err = net.Listen("tcp", cfg.webAddr()); err != nil {
			ftpLn.Close()
			return nil, err
		}
	}

	// One server failing stops the other, rather than leaving half of
	// Tiny-FTPd running.
	ctx, cancel := context.WithCancel(ctx)
	auth := fileAuth(path)
	var wg sync.WaitGroup
	var ftpErr, webErr error
	wg.Go(func() {
		defer cancel()
		srv := &ftp.Server{Auth: auth, PasvMin: cfg.PasvMin, PasvMax: cfg.PasvMax, PublicIP: cfg.PublicIP, TLS: tlsConfig, MaxConns: cfg.MaxConns}
		ftpErr = srv.Serve(ctx, ftpLn)
	})
	if webLn != nil {
		wg.Go(func() {
			defer cancel()
			srv := &web.Server{Auth: auth, TLS: tlsConfig}
			webErr = srv.Serve(ctx, webLn)
		})
	}
	return func() error {
		wg.Wait()
		return errors.Join(ftpErr, webErr)
	}, nil
}

// localIPs lists this machine's IPv4 addresses, so users know where to
// connect. Guessing the "right" one breaks with VPNs and virtual adapters.
func localIPs() []string {
	addrs, _ := net.InterfaceAddrs()
	var ips []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ips = append(ips, n.IP.String())
		}
	}
	return ips
}

func userCmd(path string, args []string) error {
	if len(args) == 0 {
		return errors.New(`expected "user add", "user rm" or "user list"`)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}

	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("user add", flag.ContinueOnError)
		flags.Usage = func() {} // main prints the usage
		readOnly := flags.Bool("readonly", false, "allow downloads only")
		start := flags.String("start", "", "folder to start in, inside the jail")
		bypass := flags.Bool("bypass-limit", false, "log in even when the server is full")
		if err := flags.Parse(args[1:]); err != nil {
			return errUsage
		}
		if flags.NArg() != 2 {
			return errors.New("usage: tinyftpd user add [-readonly] [-bypass-limit] [-start folder] <name> <folder>")
		}
		password, err := readPassword()
		if err != nil {
			return err
		}
		name := flags.Arg(0)
		if err := cfg.setUser(name, User{Name: name, Root: flags.Arg(1), Start: *start, ReadOnly: *readOnly, Bypass: *bypass}, password); err != nil {
			return err
		}
		return cfg.save(path)

	case "rm":
		if len(args) != 2 {
			return errors.New("usage: tinyftpd user rm <name>")
		}
		if !cfg.removeUser(args[1]) {
			return fmt.Errorf("no user %q", args[1])
		}
		return cfg.save(path)

	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USER\tFOLDER\tSTART\tACCESS")
		for _, u := range cfg.Users {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Name, u.Root, cmp.Or(u.Start, "/"), access(u))
		}
		return w.Flush()
	}
	return fmt.Errorf("unknown command %q", "user "+args[0])
}

// selfSignCmd creates a self-signed certificate and turns TLS on with it.
func selfSignCmd(path string) error {
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	certPath, keyPath, cert, err := selfSign(filepath.Dir(path))
	if err != nil {
		return err
	}
	cfg.TLS, cfg.TLSCert, cfg.TLSKey = true, certPath, keyPath
	if err := cfg.save(path); err != nil {
		return err
	}
	fmt.Printf("TLS is on with a self-signed certificate, valid until %s:\n  %s\n  %s\n"+
		"Clients will ask you to trust it. Check its SHA-256 fingerprint is\n  %s\n",
		cert.NotAfter.Format(time.DateOnly), certPath, keyPath, certFingerprint(cert.Raw))
	return nil
}

func access(u User) string {
	a := "Full"
	if u.ReadOnly {
		a = "Read-only"
	}
	if u.Bypass {
		a += ", no limit"
	}
	return a
}

// readPassword prompts without echo, or reads a line when stdin is piped.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if line == "" && err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}
