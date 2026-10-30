// Package web serves users' folders to browsers: a Total Commander style file
// panel with a viewer, uploads and folder management. It uses the same
// accounts and jails as FTP, and everything it needs is compiled in.
package web

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"tinyftpd/internal/jail"
	"tinyftpd/internal/pixelart"
)

// assetPrefix serves the stylesheet, script and icons. It's a dot-folder, so
// it's unlikely to clash with a real folder at the top of a jail.
const assetPrefix = "/.tiny-ftpd/"

//go:embed assets
var assets embed.FS

// assetVersion is a hash of the stylesheet and script. Pages link to them
// with it, so browsers can cache them for long and still pick up a new build.
var assetVersion = func() string {
	h := sha256.New()
	fs.WalkDir(assets, "assets/static", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := assets.ReadFile(path)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

var pages = template.Must(template.New("").Funcs(template.FuncMap{"version": func() string { return assetVersion }}).ParseFS(assets, "assets/*.html"))

// icons are the pixel-art PNGs, rendered once at start-up.
var icons = func() map[string][]byte {
	m := map[string][]byte{"app": pixelart.PNG(pixelart.Parse(pixelart.App32))}
	for name, grid := range pixelart.Icons {
		m[name] = pixelart.PNG(pixelart.Parse(grid))
	}
	return m
}()

// readTimeout is how long a client has to send a request, body included.
var readTimeout = 30 * time.Second

// Server serves the web file browser. Auth is required.
type Server struct {
	Auth jail.Auth
	// TLS, when set, makes the server HTTPS-only.
	TLS *tls.Config
	// Logger defaults to slog.Default().
	Logger *slog.Logger

	logins   loginCache
	throttle jail.Throttle // slows password guessing
}

// Serve accepts connections on ln until ctx is cancelled, then returns nil.
func (srv *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         srv.TLS,
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds reading a request, so a client can't hold a connection by
		// sending a body slowly. Uploads lift it once logged in. There's no
		// write timeout: downloads can be long.
		ReadTimeout: readTimeout,
		IdleTimeout: 2 * time.Minute,
		ErrorLog:    slog.NewLogLogger(srv.logger().Handler(), slog.LevelWarn),
	}
	context.AfterFunc(ctx, func() { hs.Close() })
	var err error
	if srv.TLS != nil {
		err = hs.ServeTLS(ln, "", "")
	} else {
		err = hs.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler returns the server's HTTP handler. State-changing requests from
// other sites are refused, so a malicious page can't use a logged-in
// browser's credentials.
func (srv *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "assets/static")
	mux := http.NewServeMux()
	mux.Handle("GET "+assetPrefix+"static/", cacheFor(http.StripPrefix(assetPrefix+"static/", http.FileServerFS(static))))
	mux.Handle("GET "+assetPrefix+"icons/{name}", cacheFor(http.HandlerFunc(serveIcon)))
	mux.HandleFunc("/", srv.files)
	return http.NewCrossOriginProtection().Handler(mux)
}

func (srv *Server) logger() *slog.Logger { return cmp.Or(srv.Logger, slog.Default()) }

func serveIcon(w http.ResponseWriter, r *http.Request) {
	b, ok := icons[r.PathValue("name")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(b)
}

func cacheFor(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		h.ServeHTTP(w, r)
	})
}

// login checks the request's Basic credentials, asking the browser for them
// if they're missing or wrong.
func (srv *Server) login(w http.ResponseWriter, r *http.Request) (user string, acct jail.Account, ok bool) {
	user, password, hasAuth := r.BasicAuth()
	if hasAuth {
		auth := func(user, password string) (jail.Account, bool) {
			return srv.throttle.Check(srv.Auth, r.RemoteAddr, user, password)
		}
		if acct, ok := srv.logins.check(auth, user, password); ok {
			return user, acct, true
		}
		// The header can hold a megabyte of username.
		srv.logger().Warn("web login failed", "remote", r.RemoteAddr, "user", user[:min(len(user), 255)])
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Tiny-FTPd", charset="UTF-8"`)
	srv.message(w, http.StatusUnauthorized, "Access denied", "Log in with your Tiny-FTPd username and password.", "")
	return "", jail.Account{}, false
}

// loginCache remembers successful logins for a minute. Browsers send the
// password with every request, and checking bcrypt for each icon and image
// would make a folder of photos crawl. User changes still apply within a
// minute. Only correct passwords are stored, so it holds at most one entry
// per user and password, and expired ones are simply overwritten.
type loginCache struct {
	mu sync.Mutex
	m  map[[32]byte]cachedLogin
}

type cachedLogin struct {
	acct  jail.Account
	until time.Time
}

const loginTTL = time.Minute

func (c *loginCache) check(auth jail.Auth, user, password string) (jail.Account, bool) {
	key := sha256.Sum256([]byte(user + "\x00" + password))
	now := time.Now()
	c.mu.Lock()
	if hit, ok := c.m[key]; ok && now.Before(hit.until) {
		c.mu.Unlock()
		return hit.acct, true
	}
	c.mu.Unlock()

	acct, ok := auth(user, password)
	if !ok {
		return jail.Account{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[[32]byte]cachedLogin{}
	}
	c.m[key] = cachedLogin{acct, now.Add(loginTTL)}
	return acct, true
}
