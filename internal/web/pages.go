package web

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"tinyftpd/internal/jail"
)

// kinds maps extensions to a kind, which picks the icon. Text is also served
// as plain text, so browsers show it rather than download or render it.
var kinds = func() map[string]string {
	m := map[string]string{}
	for kind, exts := range map[string]string{
		"image":   "jpg jpeg png gif webp bmp svg avif ico",
		"text":    "txt md log csv tsv json xml yaml yml toml ini cfg conf env go js mjs cjs ts py rb sh bat ps1 c h cpp rs java html htm css sql",
		"archive": "zip 7z rar tar gz tgz bz2 xz zst iso",
		"audio":   "mp3 flac wav ogg oga m4a aac opus",
		"video":   "mp4 m4v webm mov ogv mkv avi",
	} {
		for _, ext := range strings.Fields(exts) {
			m["."+ext] = kind
		}
	}
	return m
}()

func kindOf(name string) string {
	if ext := filepath.Ext(name); ext != name {
		return cmp.Or(kinds[strings.ToLower(ext)], "file")
	}
	return "file"
}

// request is one authenticated request.
type request struct {
	srv  *Server
	w    http.ResponseWriter
	r    *http.Request
	root *os.Root
	user string
	acct jail.Account
	log  *slog.Logger // with the remote address and user
}

func (srv *Server) files(w http.ResponseWriter, r *http.Request) {
	user, acct, ok := srv.login(w, r)
	if !ok {
		return
	}
	log := srv.logger().With("remote", r.RemoteAddr, "user", user)
	rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if r.Method != http.MethodPost { // actions log what they did instead
			log.Info("web", "method", r.Method, "path", r.URL.Path, "status", rec.status)
		}
	}()

	root, err := os.OpenRoot(acct.Root)
	if err != nil {
		log.Error("can't open folder", "err", err)
		srv.message(rec, http.StatusInternalServerError, "Folder unavailable", "Your folder isn't available right now.", "")
		return
	}
	defer root.Close()

	req := &request{srv: srv, w: rec, r: r, root: root, user: user, acct: acct, log: log}
	abs, rel := jail.Resolve("/", r.URL.Path)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		req.get(abs, rel)
	case http.MethodPost:
		req.post(abs, rel)
	default:
		srv.message(rec, http.StatusMethodNotAllowed, "Not allowed", "That request isn't supported.", "")
	}
}

func (q *request) get(abs, rel string) {
	fi, err := q.root.Stat(rel)
	if err != nil {
		q.srv.message(q.w, http.StatusNotFound, "Not found", abs+" doesn't exist.", "/")
		return
	}
	if !fi.IsDir() {
		q.download(rel)
		return
	}
	if !strings.HasSuffix(q.r.URL.Path, "/") {
		http.Redirect(q.w, q.r, href(abs, true)+querySuffix(q.r.URL.RawQuery), http.StatusMovedPermanently)
		return
	}
	// A fresh visit to the top, rather than navigating there, opens the
	// user's start folder.
	if rel == "." && q.acct.Start != "" && q.r.Header.Get("Referer") == "" && q.r.URL.RawQuery == "" {
		if start, err := q.root.Stat(strings.TrimPrefix(q.acct.Start, "/")); err == nil && start.IsDir() {
			http.Redirect(q.w, q.r, href(q.acct.Start, true), http.StatusFound)
			return
		}
	}
	q.listing(abs, rel)
}

// options are the listing's sort order and view, carried in the query.
type options struct {
	sort   string // name, size or date
	desc   bool
	thumbs bool
}

func parseOptions(v url.Values) options {
	o := options{sort: v.Get("sort"), desc: v.Has("desc"), thumbs: v.Get("view") == "thumbnails"}
	if o.sort != "size" && o.sort != "date" {
		o.sort = "name"
	}
	return o
}

// query encodes o, leaving out the defaults.
func (o options) query() string {
	v := url.Values{}
	if o.sort != "name" {
		v.Set("sort", o.sort)
	}
	if o.desc {
		v.Set("desc", "1")
	}
	if o.thumbs {
		v.Set("view", "thumbnails")
	}
	return v.Encode()
}

// layout is what every page shares: the title, the breadcrumb bar and who's
// logged in.
type layout struct {
	Title  string
	Crumbs []crumb
	User   string
	Free   string
}

type crumb struct{ Name, Href string }

// layoutFor builds the bar for the folder abs. query keeps the view and
// sort when following the breadcrumbs.
func (q *request) layoutFor(abs, query string) layout {
	l := layout{Title: abs + " · Tiny-FTPd", User: q.user, Crumbs: []crumb{{"Tiny-FTPd", "/" + query}}}
	if abs != "/" {
		parts := strings.Split(strings.Trim(abs, "/"), "/")
		for i, part := range parts {
			l.Crumbs = append(l.Crumbs, crumb{part, href("/"+strings.Join(parts[:i+1], "/"), true) + query})
		}
	}
	if free, err := jail.Free(q.root, strings.TrimPrefix(abs, "/")); err == nil {
		l.Free = humanSize(int64(free)) + " free"
	}
	return l
}

type entry struct {
	Name, Href string
	Kind       string
	Dir        bool
	Size, Date string

	size int64
	mod  time.Time
}

type listingPage struct {
	layout
	Path       string
	Parent     string
	Entries    []entry
	Thumbs     bool
	Writable   bool
	ListHref   string
	ThumbsHref string
	Columns    []column
	Action     string // form action prefix, keeping the view
	Summary    string
}

// column is a sortable header of the listing.
type column struct {
	Class, Label string
	Href         string // sorts by this column, or reverses the order if it's sorted by it already
	Arrow        string // ▲ or ▼ when the listing is sorted by it
	sort         string
}

func (q *request) listing(abs, rel string) {
	o := parseOptions(q.r.URL.Query())
	infos, err := jail.ReadDir(q.root, rel)
	if err != nil {
		q.srv.message(q.w, http.StatusInternalServerError, "Can't open this folder", jail.Reason(err), "/")
		return
	}
	query := querySuffix(o.query())
	page := listingPage{
		layout:   q.layoutFor(abs, query),
		Path:     abs,
		Thumbs:   o.thumbs,
		Writable: !q.acct.ReadOnly,
		Action:   "?action=",
	}
	if qs := o.query(); qs != "" {
		page.Action = "?" + qs + "&action="
	}
	var files, dirs int
	var total int64
	for _, fi := range infos {
		e := entry{Name: fi.Name(), Kind: kindOf(fi.Name()), Date: fi.ModTime().Format("2 Jan 2006, 15:04"), size: fi.Size(), mod: fi.ModTime()}
		if fi.IsDir() {
			e.Dir, e.Kind = true, "folder"
			e.Href = href(joined(abs, e.Name), true) + query
			dirs++
		} else {
			e.Size = humanSize(fi.Size())
			e.Href = href(joined(abs, e.Name), false)
			files++
			total += fi.Size()
		}
		page.Entries = append(page.Entries, e)
	}
	slices.SortStableFunc(page.Entries, func(a, b entry) int {
		if a.Dir != b.Dir { // folders first, whatever the order
			if a.Dir {
				return -1
			}
			return 1
		}
		var c int
		switch o.sort {
		case "size":
			c = cmp.Compare(a.size, b.size)
		case "date":
			c = a.mod.Compare(b.mod)
		}
		if c == 0 {
			c = cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		}
		if o.desc {
			c = -c
		}
		return c
	})

	if abs != "/" {
		page.Parent = href(path.Dir(abs), true) + query
	}
	list, thumbs := o, o
	list.thumbs, thumbs.thumbs = false, true
	page.ListHref, page.ThumbsHref = "?"+list.query(), "?"+thumbs.query()
	arrow := " \u25b2"
	if o.desc {
		arrow = " \u25bc"
	}
	page.Columns = []column{{Label: "Name", sort: "name"}, {Class: "size", Label: "Size", sort: "size"}, {Class: "date", Label: "Modified", sort: "date"}}
	for i, c := range page.Columns {
		s := o
		s.sort, s.desc = c.sort, c.sort == o.sort && !o.desc
		page.Columns[i].Href = "?" + s.query()
		if c.sort == o.sort {
			page.Columns[i].Arrow = arrow
		}
	}
	page.Summary = fmt.Sprintf("%s, %s, %s.", plural(dirs, "folder"), plural(files, "file"), humanSize(total))
	q.srv.render(q.w, http.StatusOK, "listing", page)
}

// askPage asks before deleting, or for a name when renaming or making a
// folder. JavaScript asks with the browser's own dialogs instead; these
// pages are the fallback.
type askPage struct {
	layout
	Path, Action string
	Names        []string
	Back         string
}

func (q *request) ask(page, abs string, names []string) {
	query := querySuffix(parseOptions(q.r.URL.Query()).query())
	q.srv.render(q.w, http.StatusOK, page, askPage{
		layout: q.layoutFor(abs, query),
		Path:   abs, Action: "?" + q.r.URL.RawQuery, Names: names,
		Back: href(abs, true) + query,
	})
}

// download serves a file, with range requests so videos can seek. Text is
// served as plain text, so browsers show it instead of downloading or
// rendering it. Everything is sandboxed: an uploaded HTML or SVG file can't
// run scripts as this site.
func (q *request) download(rel string) {
	f, err := jail.Open(q.root, rel)
	if err != nil {
		q.srv.message(q.w, http.StatusNotFound, "Not Found", jail.Reason(err), "")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		q.srv.message(q.w, http.StatusNotFound, "Not Found", jail.Reason(err), "")
		return
	}
	h := q.w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin") // other sites can't probe for files
	if kindOf(fi.Name()) == "text" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	if q.r.URL.Query().Has("download") {
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fi.Name()}))
	}
	http.ServeContent(q.w, q.r, fi.Name(), fi.ModTime(), f)
}

// post runs an action on the folder abs: upload, mkdir, rename, delete or
// download. Actions that need a name or a confirmation show a page asking
// for it when the form didn't include one.
func (q *request) post(abs, rel string) {
	action := q.r.URL.Query().Get("action")
	back := href(abs, true) + querySuffix(parseOptions(q.r.URL.Query()).query())
	if q.acct.ReadOnly && action != "download" {
		q.log.Warn("web action refused", "action", action, "folder", abs, "err", "read-only")
		q.srv.message(q.w, http.StatusForbidden, "Read-only", "You can only download from this server.", back)
		return
	}
	if fi, err := q.root.Stat(rel); err != nil || !fi.IsDir() {
		q.srv.message(q.w, http.StatusNotFound, "Not found", abs+" isn't a folder.", "/")
		return
	}

	if action == "upload" {
		// Uploads can take as long as they need; the server's read timeout
		// is for everyone else, including people who haven't logged in.
		http.NewResponseController(q.w).SetReadDeadline(time.Time{})
		q.finish(q.upload(abs), back)
		return
	}
	q.r.ParseForm()
	names := q.r.PostForm["name"]
	switch action {
	case "mkdir":
		folder := strings.TrimSpace(q.r.PostForm.Get("folder"))
		if folder == "" {
			q.ask("mkdir", abs, nil)
			return
		}
		_, dir, err := child(abs, folder)
		if err == nil {
			err = jail.Mkdir(q.root, dir)
		}
		q.finish(q.logged(err, "web mkdir", "folder", joined(abs, folder)), back)
	case "rename":
		if len(names) != 1 {
			q.finish(errors.New("tick one item to rename"), back)
			return
		}
		to := strings.TrimSpace(q.r.PostForm.Get("to"))
		if to == "" {
			q.ask("rename", abs, names)
			return
		}
		_, from, err := child(abs, names[0])
		if err == nil {
			var dest string
			if _, dest, err = child(abs, to); err == nil {
				err = q.root.Rename(from, dest)
			}
		}
		q.finish(q.logged(err, "web rename", "from", joined(abs, names[0]), "to", joined(abs, to)), back)
	case "delete":
		if len(names) == 0 {
			q.finish(errors.New("tick what you want to delete"), back)
			return
		}
		if q.r.PostForm.Get("confirm") != "1" {
			q.ask("delete", abs, names)
			return
		}
		var errs []error
		for _, name := range names {
			_, rel, err := child(abs, name)
			if err == nil {
				err = q.root.Remove(rel) // files, or empty folders
			}
			if q.logged(err, "web delete", "path", joined(abs, name)) != nil {
				errs = append(errs, fmt.Errorf("%s: %s", name, jail.Reason(err)))
			}
		}
		q.finish(errors.Join(errs...), back)
	case "download":
		if len(names) != 1 {
			q.finish(errors.New("tick one file to download"), back)
			return
		}
		fileAbs, _, err := child(abs, names[0])
		if err != nil {
			q.finish(err, back)
			return
		}
		http.Redirect(q.w, q.r, href(fileAbs, false)+"?download", http.StatusSeeOther)
	default:
		q.finish(fmt.Errorf("unknown action %q", action), back)
	}
}

// finish goes back to the folder, or explains what went wrong.
func (q *request) finish(err error, back string) {
	if err != nil {
		q.srv.message(q.w, http.StatusBadRequest, "That didn't work", jail.Reason(err), back)
		return
	}
	http.Redirect(q.w, q.r, back, http.StatusSeeOther)
}

// upload streams every file in a multipart request into the folder abs.
func (q *request) upload(abs string) error {
	mr, err := q.r.MultipartReader()
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	n := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if part.FormName() != "file" || part.FileName() == "" {
			continue
		}
		written, err := q.save(abs, part, buf)
		if q.logged(err, "web upload", "file", joined(abs, part.FileName()), "bytes", written) != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errors.New("no files to upload")
	}
	return nil
}

// save writes one uploaded file into the folder abs. It goes into a
// temporary file that replaces the real one once complete, so a failed
// upload leaves an existing file as it was.
func (q *request) save(abs string, part *multipart.Part, buf []byte) (int64, error) {
	_, rel, err := child(abs, part.FileName())
	if err != nil {
		return 0, err
	}
	tmp := path.Join(path.Dir(rel), fmt.Sprintf(".tiny-ftpd-%016x.part", rand.Uint64()))
	f, err := jail.Create(q.root, tmp)
	if err != nil {
		return 0, err
	}
	defer q.root.Remove(tmp) // fails harmlessly after the rename
	// Hiding ReadFrom makes CopyBuffer use the 1 MiB buffer.
	written, err := io.CopyBuffer(struct{ io.Writer }{f}, part, buf)
	if err := errors.Join(err, f.Close()); err != nil {
		return written, err
	}
	if fi, err := q.root.Stat(rel); err == nil && fi.Mode().IsRegular() {
		q.root.Chmod(tmp, fi.Mode().Perm()) // keep the replaced file's permissions
	}
	return written, q.root.Rename(tmp, rel)
}

// joined is name in the folder dir. Unlike path.Join it leaves the name as
// it is, so a refused "../x" is logged as such.
func joined(dir, name string) string { return strings.TrimSuffix(dir, "/") + "/" + name }

// logged logs a change to the folder and passes err through: info when it
// worked, a warning with the reason when it didn't.
func (q *request) logged(err error, msg string, args ...any) error {
	if err != nil {
		q.log.Warn(msg, append(args, "err", jail.Reason(err))...)
	} else {
		q.log.Info(msg, args...)
	}
	return err
}

// child resolves name inside dir, refusing anything but a plain file name.
// The name is taken as it is: " a.txt" and "a.txt" are different files.
func child(dir, name string) (abs, rel string, err error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", "", fmt.Errorf("%q isn't a valid name", name)
	}
	abs, rel = jail.Resolve(dir, name)
	return abs, rel, nil
}

type messagePage struct {
	layout
	Heading, Text, Back string
}

func (srv *Server) message(w http.ResponseWriter, status int, heading, text, back string) {
	l := layout{Title: heading + " · Tiny-FTPd", Crumbs: []crumb{{"Tiny-FTPd", "/"}}}
	srv.render(w, status, "message", messagePage{layout: l, Heading: heading, Text: text, Back: back})
}

// render writes a page with a strict Content-Security-Policy: our own
// stylesheet, script and images, nothing inline and nothing from elsewhere.
func (srv *Server) render(w http.ResponseWriter, status int, name string, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		srv.logger().Error("web page", "page", name, "err", err)
	}
}

// href returns the escaped URL path for abs, a path inside the jail.
func href(abs string, dir bool) string {
	parts := strings.Split(strings.Trim(abs, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	h := "/" + strings.Join(parts, "/")
	if dir && h != "/" {
		h += "/"
	}
	return h
}

func querySuffix(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

// humanSize formats a byte count for people: 3 bytes, 13 KB, 46.2 MB.
func humanSize(n int64) string {
	switch {
	case n == 1:
		return "1 byte"
	case n < 1024:
		return strconv.FormatInt(n, 10) + " bytes"
	case n < 1024*1024:
		return fmt.Sprintf("%.0f KB", float64(n)/1024)
	}
	v, unit := float64(n)/(1<<20), "MB"
	for _, bigger := range []string{"GB", "TB"} {
		if v < 1024 {
			break
		}
		v, unit = v/1024, bigger
	}
	return fmt.Sprintf("%.1f %s", v, unit)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// statusWriter records the response status for the request log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// ReadFrom keeps the underlying writer's fast path, such as sendfile.
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) { return io.Copy(w.ResponseWriter, r) }

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
