package web

import (
	"bytes"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tinyftpd/internal/jail"
)

// start serves a jail with users "rw" and "ro" (password "pw") and returns
// the server URL, the jail folder and the server's log.
func start(t *testing.T) (string, string, *logBuffer) {
	t.Helper()
	root := t.TempDir()
	srv := &Server{
		Auth: func(user, password string) (jail.Account, bool) {
			if password != "pw" || (user != "rw" && user != "ro") {
				return jail.Account{}, false
			}
			return jail.Account{Root: root, ReadOnly: user == "ro"}, true
		},
	}
	log := &logBuffer{}
	srv.Logger = slog.New(slog.NewTextHandler(log, nil))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, root, log
}

// logBuffer collects log lines written from the server's goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func do(t *testing.T, method, url, user string, body io.Reader, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	must(t, err)
	if user != "" {
		req.SetBasicAuth(user, "pw")
	}
	for k, v := range header {
		req.Header[k] = v
	}
	// Don't follow redirects, so tests see them.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	must(t, err)
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	must(t, err)
	return res, string(b)
}

func TestBrowse(t *testing.T) {
	base, root, _ := start(t)
	must(t, os.MkdirAll(filepath.Join(root, "photos"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "photos", "cat.jpg"), []byte("meow"), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hello <b>world</b>"), 0o644))
	must(t, os.WriteFile(filepath.Join(filepath.Dir(root), "secret.txt"), []byte("secret"), 0o644))

	if res, _ := do(t, "GET", base+"/", "", nil, nil); res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no login prompt: %d", res.StatusCode)
	}
	if res, _ := do(t, "GET", base+"/", "nobody", nil, nil); res.StatusCode != 401 {
		t.Fatalf("bad login got %d", res.StatusCode)
	}

	res, page := do(t, "GET", base+"/", "ro", nil, nil)
	for _, want := range []string{`href="/photos/">photos</a>`, `href="/notes.txt">notes.txt</a>`, "1 folder, 1 file, 18 bytes."} {
		if !strings.Contains(page, want) {
			t.Fatalf("listing (%d) lacks %q:\n%s", res.StatusCode, want, page)
		}
	}
	if strings.Contains(page, `name="name"`) || strings.Contains(page, "Upload files") {
		t.Error("read-only user can select or upload")
	}
	// Our own script and uploads with progress are allowed; nothing else.
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP: %q", csp)
	}
	if _, page := do(t, "GET", base+"/photos/", "ro", nil, nil); !strings.Contains(page, `<a href="/">..</a>`) || !strings.Contains(page, `<a href="/photos/">photos</a>`) {
		t.Errorf("subfolder has no parent row or breadcrumb:\n%s", page)
	}
	if _, page := do(t, "GET", base+"/photos/?view=thumbnails", "ro", nil, nil); !strings.Contains(page, `<img class="pic" src="/photos/cat.jpg"`) {
		t.Errorf("thumbnails:\n%s", page)
	}

	// Files are sandboxed, text shows as plain text, and ranges work so
	// videos can seek.
	res, body := do(t, "GET", base+"/notes.txt", "ro", nil, http.Header{"Range": {"bytes=0-4"}})
	if res.StatusCode != 206 || body != "hello" || res.Header.Get("Content-Security-Policy") != "sandbox" || res.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("file: %d %q %v", res.StatusCode, body, res.Header)
	}
	if res, _ := do(t, "GET", base+"/notes.txt?download", "ro", nil, nil); !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") {
		t.Error("?download doesn't download")
	}

	// Paths can't climb out of the jail.
	for _, p := range []string{"/../secret.txt", "/..%2fsecret.txt", "/photos/../../secret.txt"} {
		if res, body := do(t, "GET", base+p, "ro", nil, nil); res.StatusCode == 200 && body == "secret" {
			t.Errorf("%s escaped the jail", p)
		}
	}

	if res, _ := do(t, "GET", base+"/.tiny-ftpd/icons/folder", "", nil, nil); res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" {
		t.Errorf("icon: %d", res.StatusCode)
	}
}

func TestChanges(t *testing.T) {
	base, root, log := start(t)
	post := func(user, action string, fields ...string) (*http.Response, string) {
		v := url.Values{}
		for i := 0; i < len(fields); i += 2 {
			v.Add(fields[i], fields[i+1])
		}
		return do(t, "POST", base+"/?action="+action, user, strings.NewReader(v.Encode()),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(root, name))
		return err == nil
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "up.txt")
	fw.Write([]byte("uploaded"))
	mw.Close()
	uploadHeader := http.Header{"Content-Type": {mw.FormDataContentType()}}
	if res, _ := do(t, "POST", base+"/?action=upload", "ro", bytes.NewReader(body.Bytes()), uploadHeader); res.StatusCode != 403 {
		t.Errorf("read-only upload got %d", res.StatusCode)
	}
	if res, _ := do(t, "POST", base+"/?view=thumbnails&action=upload", "rw", bytes.NewReader(body.Bytes()), uploadHeader); res.StatusCode != 303 || res.Header.Get("Location") != "/?view=thumbnails" {
		t.Fatalf("upload got %d, back to %q", res.StatusCode, res.Header.Get("Location"))
	}
	if got, _ := os.ReadFile(filepath.Join(root, "up.txt")); string(got) != "uploaded" {
		t.Fatalf("uploaded %q", got)
	}

	// Without an answer from JavaScript, actions ask on a page first.
	if _, page := post("rw", "mkdir"); !strings.Contains(page, `name="folder"`) {
		t.Errorf("mkdir without a name:\n%s", page)
	}
	if _, page := post("rw", "rename", "name", "up.txt"); !strings.Contains(page, `name="to" value="up.txt"`) {
		t.Errorf("rename without a new name:\n%s", page)
	}
	if _, page := post("rw", "delete", "name", "up.txt"); !strings.Contains(page, `name="confirm" value="1"`) || !exists("up.txt") {
		t.Errorf("delete without confirming:\n%s", page)
	}

	for _, step := range [][]string{
		{"mkdir", "folder", "a"},
		{"mkdir", "folder", "b"},
		{"rename", "name", "up.txt", "to", "renamed.txt"},
		{"delete", "name", "a", "name", "b", "confirm", "1"}, // several at once
	} {
		if res, page := post("rw", step[0], step[1:]...); res.StatusCode != 303 {
			t.Fatalf("%v got %d:\n%s", step, res.StatusCode, page)
		}
	}
	if !exists("renamed.txt") || exists("a") || exists("b") {
		t.Error("changes didn't land")
	}
	if res, _ := post("ro", "download", "name", "renamed.txt"); res.StatusCode != 303 || res.Header.Get("Location") != "/renamed.txt?download" {
		t.Errorf("download got %d to %q", res.StatusCode, res.Header.Get("Location"))
	}

	if res, _ := post("rw", "mkdir", "folder", "../escape"); res.StatusCode != 400 {
		t.Errorf("mkdir with a path got %d", res.StatusCode)
	}
	for _, want := range []string{
		`level=INFO msg="web upload" remote=`,
		`user=rw file=/up.txt bytes=8`,
		`msg="web mkdir" remote=`,
		`user=rw folder=/a`,
		`user=rw from=/up.txt to=/renamed.txt`,
		`user=rw path=/b`,
		`level=WARN msg="web action refused"`,
		`action=upload`,
		`folder=/../escape err="\"../escape\" isn't a valid name"`,
	} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %s:\n%s", want, log)
		}
	}
	if res, _ := post("rw", "rename", "name", "a", "name", "b", "to", "c"); res.StatusCode != 400 {
		t.Errorf("renaming two things got %d", res.StatusCode)
	}

	// Another site can't make a logged-in browser change files.
	crossSite := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Sec-Fetch-Site": {"cross-site"}}
	if res, _ := do(t, "POST", base+"/?action=mkdir", "rw", strings.NewReader("folder=evil"), crossSite); res.StatusCode != 403 {
		t.Errorf("cross-site POST got %d", res.StatusCode)
	}
}

// Names are taken exactly as sent, so acting on " a.txt" leaves "a.txt" alone.
func TestExactNames(t *testing.T) {
	base, root, _ := start(t)
	for _, name := range []string{" a.txt", "a.txt"} {
		must(t, os.WriteFile(filepath.Join(root, name), nil, 0o644))
	}
	v := url.Values{"name": {" a.txt"}, "confirm": {"1"}}
	res, _ := do(t, "POST", base+"/?action=delete", "rw", strings.NewReader(v.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	_, errSpaced := os.Stat(filepath.Join(root, " a.txt"))
	_, errPlain := os.Stat(filepath.Join(root, "a.txt"))
	if res.StatusCode != 303 || errSpaced == nil || errPlain != nil {
		t.Errorf("delete got %d, spaced name gone: %v, plain name kept: %v", res.StatusCode, errSpaced != nil, errPlain == nil)
	}
}

func TestFailedUploadKeepsFile(t *testing.T) {
	base, root, _ := start(t)
	must(t, os.WriteFile(filepath.Join(root, "precious.txt"), []byte("precious"), 0o644))

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "precious.txt")
	fw.Write([]byte("x")) // and no closing boundary: the upload broke off
	res, _ := do(t, "POST", base+"/?action=upload", "rw", &body, http.Header{"Content-Type": {mw.FormDataContentType()}})
	if res.StatusCode != 400 {
		t.Errorf("broken upload got %d", res.StatusCode)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "precious.txt")); string(got) != "precious" {
		t.Errorf("broken upload left %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(root, ".*")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
