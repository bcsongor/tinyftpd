package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"tinyftpd/internal/ftp"
)

// Config is the tinyftpd.json file. The server re-reads it on every login, so
// user changes apply without a restart.
type Config struct {
	ListenIP string `json:"listenIP,omitempty"` // empty listens on all addresses
	Port     int    `json:"port"`
	PasvMin  int    `json:"pasvMin,omitempty"`
	PasvMax  int    `json:"pasvMax,omitempty"`
	PublicIP string `json:"publicIP,omitempty"`
	MaxConns int    `json:"maxConnections"`           // users logged in at once, 0 for no limit
	Web      bool   `json:"web,omitempty"`            // serve the web file browser
	WebPort  int    `json:"webPort,omitempty"`        // port for the web browser
	TLS      bool   `json:"tls,omitempty"`            // require explicit FTPS
	TLSCert  string `json:"tlsCert,omitempty"`        // PEM certificate, chain included
	TLSKey   string `json:"tlsKey,omitempty"`         // PEM private key
	TLSPQ    bool   `json:"tlsPostQuantum,omitempty"` // require post-quantum key exchange
	Users    []User `json:"users"`
}

// User is an account and the folder it's jailed to.
type User struct {
	Name     string `json:"name"`
	Hash     string `json:"hash"`            // bcrypt
	Root     string `json:"root"`            // absolute folder the user is jailed to
	Start    string `json:"start,omitempty"` // folder to start in, inside the jail, e.g. "/photos"
	ReadOnly bool   `json:"readOnly,omitempty"`
	Bypass   bool   `json:"bypassLimit,omitempty"` // logs in even when the server is full
}

// defaultConfigPath keeps the config next to the binary, so tinyftpd stays a
// single portable file.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "tinyftpd.json"
	}
	return filepath.Join(filepath.Dir(exe), "tinyftpd.json")
}

// loadConfig reads the config at path. A missing file gives the defaults.
func loadConfig(path string) (Config, error) {
	cfg := Config{Port: 21, MaxConns: 50, WebPort: 8080}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// validate checks the server settings. The CLI and the GUI both call it, so
// a hand-edited config can't slip past rules the Settings dialog enforces.
func (c Config) validate() error {
	var errs []error
	if !validPort(c.Port) {
		errs = append(errs, fmt.Errorf("port %d must be between 1 and 65535", c.Port))
	}
	if c.Web && !validPort(c.WebPort) {
		errs = append(errs, fmt.Errorf("web port %d must be between 1 and 65535", c.WebPort))
	}
	if c.Web && c.WebPort == c.Port {
		errs = append(errs, errors.New("the web browser needs a different port from FTP"))
	}
	if c.MaxConns < 0 {
		errs = append(errs, errors.New("maximum connections can't be negative, use 0 for no limit"))
	}
	if (c.PasvMin != 0 || c.PasvMax != 0) && (!validPort(c.PasvMin) || !validPort(c.PasvMax) || c.PasvMin > c.PasvMax) {
		errs = append(errs, fmt.Errorf("passive ports %d-%d must be a range within 1-65535", c.PasvMin, c.PasvMax))
	}
	for _, ip := range []string{c.ListenIP, c.PublicIP} {
		if ip != "" && net.ParseIP(ip) == nil {
			errs = append(errs, fmt.Errorf("%q isn't an IP address", ip))
		}
	}
	return errors.Join(errs...)
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// clone returns a copy of c that shares no users with it, for changes that
// only take effect once saved.
func (c Config) clone() Config {
	c.Users = slices.Clone(c.Users)
	return c
}

func (c Config) listenAddr() string {
	return net.JoinHostPort(c.ListenIP, strconv.Itoa(c.Port))
}

func (c Config) webAddr() string {
	return net.JoinHostPort(c.ListenIP, strconv.Itoa(c.WebPort))
}

// addresses describes where clients can connect. ftpes:// is the usual
// scheme for explicit FTPS.
func (c Config) addresses() string {
	ftpScheme, webScheme := "ftp", "http"
	if c.TLS {
		ftpScheme, webScheme = "ftpes", "https"
	}
	if c.ListenIP != "" {
		s := ftpScheme + "://" + c.listenAddr()
		if c.Web {
			s += " and " + webScheme + "://" + c.webAddr()
		}
		return s
	}
	s := fmt.Sprintf("port %d", c.Port)
	if c.Web {
		s += fmt.Sprintf(" (web %d)", c.WebPort)
	}
	s += " on " + strings.Join(localIPs(), ", ")
	if c.TLS {
		s += ", TLS required"
	}
	return s
}

// tlsConfig loads the certificate when TLS is on, and returns nil when off.
func (c Config) tlsConfig() (*tls.Config, error) {
	if !c.TLS {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if c.TLSPQ {
		// ML-KEM hybrids only exist in TLS 1.3.
		cfg.MinVersion, cfg.CurvePreferences = tls.VersionTLS13, ftp.PostQuantumKeyExchanges
	}
	return cfg, nil
}

// save writes the config atomically, so a login reading it mid-save never
// sees a partial file.
func (c Config) save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), 0o600)
}

// writeFile replaces path with data via a temporary file renamed over it. A
// crash leaves the old file intact, a symlink at path is replaced rather than
// followed, and the data is never readable with looser permissions than mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*") // mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err := errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (c Config) find(name string) int {
	return slices.IndexFunc(c.Users, func(u User) bool { return u.Name == name })
}

// setUser validates u and stores it, replacing the user named old if there is
// one. An empty password keeps the replaced user's password.
func (c *Config) setUser(old string, u User, password string) error {
	u.Name = strings.TrimSpace(u.Name)
	if u.Name == "" {
		return errors.New("username is required")
	}
	i := c.find(old)
	if j := c.find(u.Name); j >= 0 && j != i {
		return fmt.Errorf("user %q already exists", u.Name)
	}

	if strings.TrimSpace(u.Root) == "" {
		return errors.New("folder is required")
	}
	root, err := filepath.Abs(strings.TrimSpace(u.Root))
	if err != nil {
		return err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return fmt.Errorf("%q is not a folder", u.Root)
	}
	u.Root = root
	if u.Start, err = startDir(root, strings.TrimSpace(u.Start)); err != nil {
		return err
	}

	switch {
	case password != "":
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Hash = string(hash)
	case i >= 0:
		u.Hash = c.Users[i].Hash
	default:
		return errors.New("password is required")
	}

	if i >= 0 {
		c.Users[i] = u
	} else {
		c.Users = append(c.Users, u)
	}
	return nil
}

// startDir turns a start folder, given as a full path or a path inside root,
// into a path within the jail like "/photos". The jail root itself is "".
// It checks the folder through os.Root, as the servers do, so a symlink out
// of the jail is refused here rather than ignored at login.
func startDir(root, start string) (string, error) {
	if start == "" {
		return "", nil
	}
	rel := strings.TrimLeft(start, string(filepath.Separator)+"/") // "photos" or "/photos"
	if r, err := filepath.Rel(root, start); err == nil && filepath.IsAbs(start) && filepath.IsLocal(r) {
		rel = r // a full path inside root
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("start folder %q must be inside the jail folder", start)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer r.Close()
	if fi, err := r.Stat(rel); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("start folder %q is not a folder", start)
	}
	if rel = filepath.Clean(rel); rel == "." {
		return "", nil
	}
	return "/" + filepath.ToSlash(rel), nil
}

func (c *Config) removeUser(name string) bool {
	n := len(c.Users)
	c.Users = slices.DeleteFunc(c.Users, func(u User) bool { return u.Name == name })
	return len(c.Users) < n
}

// bcryptSlots caps concurrent password checks, so a flood of logins can't
// take every core.
var bcryptSlots = make(chan struct{}, runtime.NumCPU())

// dummyHash is checked for unknown users, so a wrong username takes as long
// as a wrong password and doesn't reveal which users exist.
var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("tinyftpd"), bcrypt.DefaultCost)
	return h
})

func (c Config) authenticate(name, password string) (User, bool) {
	// bcrypt ignores bytes past the 72nd and repeats short passwords with a
	// NUL between copies, so either would let variants of a password match.
	if len(password) > 72 || strings.ContainsRune(password, 0) {
		return User{}, false
	}
	var u User
	hash := dummyHash()
	i := c.find(name)
	if i >= 0 {
		u = c.Users[i]
		hash = []byte(u.Hash)
	}
	bcryptSlots <- struct{}{}
	err := bcrypt.CompareHashAndPassword(hash, []byte(password))
	<-bcryptSlots
	return u, i >= 0 && err == nil
}
