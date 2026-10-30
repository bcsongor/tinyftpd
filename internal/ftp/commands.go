package ftp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"tinyftpd/internal/jail"
)

type command struct {
	fn    func(s *session, arg string)
	login bool // needs a logged-in user
	write bool // modifies files, refused for read-only users
}

// Replies follow Pure-FTPd's wording where it has one.
var commands = map[string]command{
	"USER":    {fn: (*session).user},
	"PASS":    {fn: (*session).pass},
	"QUIT":    {fn: (*session).quit},
	"NOOP":    {fn: (*session).noop},
	"SYST":    {fn: (*session).syst},
	"FEAT":    {fn: (*session).feat},
	"OPTS":    {fn: (*session).opts},
	"ABOR":    {fn: (*session).abor},
	"AUTH":    {fn: (*session).auth},
	"PBSZ":    {fn: (*session).pbsz},
	"PROT":    {fn: (*session).prot},
	"TYPE":    {fn: (*session).typ, login: true},
	"PWD":     {fn: (*session).pwd, login: true},
	"XPWD":    {fn: (*session).pwd, login: true},
	"CWD":     {fn: (*session).cwd, login: true},
	"XCWD":    {fn: (*session).cwd, login: true},
	"CDUP":    {fn: (*session).cdup, login: true},
	"XCUP":    {fn: (*session).cdup, login: true},
	"PASV":    {fn: (*session).pasv, login: true},
	"EPSV":    {fn: (*session).epsv, login: true},
	"LIST":    {fn: (*session).list, login: true},
	"NLST":    {fn: (*session).nlst, login: true},
	"MLSD":    {fn: (*session).mlsd, login: true},
	"MLST":    {fn: (*session).mlst, login: true},
	"SIZE":    {fn: (*session).size, login: true},
	"AVBL":    {fn: (*session).avbl, login: true},
	"MDTM":    {fn: (*session).mdtm, login: true},
	"MFMT":    {fn: (*session).mfmt, login: true, write: true},
	"HASH":    {fn: (*session).hash, login: true},
	"XCRC":    {fn: xhash("CRC32"), login: true},
	"XMD5":    {fn: xhash("MD5"), login: true},
	"XSHA1":   {fn: xhash("SHA-1"), login: true},
	"XSHA256": {fn: xhash("SHA-256"), login: true},
	"XSHA512": {fn: xhash("SHA-512"), login: true},
	"REST":    {fn: (*session).rest, login: true},
	"RETR":    {fn: (*session).retr, login: true},
	"STOR":    {fn: (*session).stor, login: true, write: true},
	"DELE":    {fn: (*session).dele, login: true, write: true},
	"MKD":     {fn: (*session).mkd, login: true, write: true},
	"XMKD":    {fn: (*session).mkd, login: true, write: true},
	"RMD":     {fn: (*session).rmd, login: true, write: true},
	"XRMD":    {fn: (*session).rmd, login: true, write: true},
	"RNFR":    {fn: (*session).rnfr, login: true, write: true},
	"RNTO":    {fn: (*session).rnto, login: true, write: true},
	"SITE":    {fn: (*session).site, login: true, write: true}, // only SITE CHMOD
}

func (s *session) user(arg string) {
	if s.srv.TLS != nil && !s.secure {
		s.reply(530, "This server requires TLS, use AUTH TLS first")
		return
	}
	if len(arg) > 255 {
		s.reply(501, "Username too long")
		return
	}
	// Switching user would restart the login without its time limit.
	if s.root != nil {
		s.reply(503, "You're already logged in")
		return
	}
	s.username = arg
	s.reply(331, "User %s OK. Password required", arg)
}

func (s *session) pass(arg string) {
	if s.username == "" {
		s.reply(503, "Login with USER first")
		return
	}
	if s.root != nil {
		s.reply(503, "You're already logged in")
		return
	}
	acct, ok := s.srv.throttle.Check(s.srv.Auth, s.conn.RemoteAddr().String(), s.username, arg)
	if !ok {
		s.log.Warn("login failed", "user", s.username)
		s.reply(530, "Login authentication failed")
		return
	}
	if s.srv.MaxConns > 0 && !acct.BypassLimit {
		if s.srv.loggedIn.Add(1) > int64(s.srv.MaxConns) {
			s.srv.loggedIn.Add(-1)
			s.log.Warn("login refused, server full", "user", s.username)
			s.reply(421, "%d users (the maximum) are already logged in, sorry", s.srv.MaxConns)
			s.conn.Close()
			return
		}
		s.counted = true
	}
	root, err := os.OpenRoot(acct.Root)
	if err != nil {
		s.log.Error("can't open folder", "user", s.username, "err", err)
		s.reply(530, "Home directory not available")
		s.logout()
		return
	}
	s.loginDone()
	s.log = s.srv.logger().With("remote", s.conn.RemoteAddr().String(), "user", s.username)
	s.root, s.readOnly, s.dir = root, acct.ReadOnly, "/"
	if acct.Start != "" {
		abs, rel := s.resolve(acct.Start)
		if fi, err := root.Stat(rel); err == nil && fi.IsDir() {
			s.dir = abs
		} else {
			s.log.Warn("start folder unavailable, starting at /", "start", acct.Start)
		}
	}
	s.log.Info("logged in")
	s.reply(230, "OK. Current directory is %s", s.dir)
}

func (s *session) quit(string) {
	s.replyLines(221,
		fmt.Sprintf("Goodbye. You uploaded %d and downloaded %d kbytes.", (s.up+1023)/1024, (s.down+1023)/1024),
		"Logout.",
	)
	s.conn.Close()
}

func (s *session) noop(string) { s.reply(200, "Zzz...") }
func (s *session) syst(string) { s.reply(215, "UNIX Type: L8") }
func (s *session) abor(string) { s.reply(226, "Since you see this ABOR must've succeeded") }

func (s *session) feat(string) {
	lines := []string{"Extensions supported:",
		" EPSV", " PASV", " SIZE", " MDTM", " MFMT", " REST STREAM", " UTF8", " AVBL",
		" MLST " + strings.ReplaceAll(mlstFacts, ";", "*;"),
		" HASH " + s.hashList(),
		" XCRC", " XMD5", " XSHA1", " XSHA256", " XSHA512",
	}
	if s.srv.TLS != nil {
		lines = append(lines, " AUTH TLS", " PBSZ", " PROT")
	}
	s.replyLines(211, append(lines, "End.")...)
}

func (s *session) opts(arg string) {
	name, value, _ := strings.Cut(arg, " ")
	switch strings.ToUpper(name) {
	case "UTF8":
		s.reply(200, "OK, UTF-8 enabled")
	case "MLST":
		s.reply(200, "MLST OPTS %s", mlstFacts) // we always send every fact
	case "HASH":
		s.optsHash(value)
	default:
		s.reply(501, "Unknown option")
	}
}

// typ accepts ASCII but transfers everything as binary, like most modern
// servers. No line-ending conversion keeps transfers fast.
func (s *session) typ(arg string) {
	t, _, _ := strings.Cut(strings.ToUpper(arg), " ")
	switch t {
	case "I", "L":
		s.reply(200, "TYPE is now 8-bit binary")
	case "A":
		s.reply(200, "TYPE is now ASCII")
	default:
		s.reply(504, "Unknown TYPE: %s", arg)
	}
}

func (s *session) pwd(string) {
	s.reply(257, "%s is your current location", quote(s.dir))
}

func (s *session) cwd(arg string) {
	abs, rel := s.resolve(arg)
	if fi, err := s.root.Stat(rel); err != nil || !fi.IsDir() {
		s.reply(550, "Can't change directory to %s: No such file or directory", arg)
		return
	}
	s.dir = abs
	s.reply(250, "OK. Current directory is %s", abs)
}

func (s *session) cdup(string) { s.cwd("..") }

func (s *session) pasv(string) {
	ip := s.conn.LocalAddr().(*net.TCPAddr).IP
	if s.srv.PublicIP != "" {
		ip = net.ParseIP(s.srv.PublicIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		s.reply(425, "PASV needs IPv4, use EPSV")
		return
	}
	if port, ok := s.listen(); ok {
		s.reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip4[0], ip4[1], ip4[2], ip4[3], port>>8, port&0xff)
	}
}

func (s *session) epsv(string) {
	if port, ok := s.listen(); ok {
		s.reply(229, "Extended Passive mode OK (|||%d|)", port)
	}
}

func (s *session) list(arg string) {
	now := time.Now()
	s.sendListing(arg, func(fi fs.FileInfo) string { return longEntry(fi, now) })
}

func (s *session) nlst(arg string) {
	s.sendListing(arg, func(fi fs.FileInfo) string { return fi.Name() + "\r\n" })
}

func (s *session) sendListing(arg string, format func(fs.FileInfo) string) {
	// Clients send ls flags like "-la"; we always list everything.
	for strings.HasPrefix(arg, "-") {
		_, arg, _ = strings.Cut(arg, " ")
	}
	_, rel := s.resolve(arg)
	infos, err := s.readDir(rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	_, ok := s.transfer(func(c net.Conn) (int64, error) {
		w := bufio.NewWriter(c)
		for _, fi := range infos {
			w.WriteString(format(fi))
		}
		return 0, w.Flush()
	})
	if ok {
		s.reply(226, "%d matches total", len(infos))
	}
}

// readDir lists rel, or returns rel itself if it's a file, like ls does.
func (s *session) readDir(rel string) ([]fs.FileInfo, error) {
	fi, err := s.root.Stat(rel)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []fs.FileInfo{fi}, nil
	}
	return jail.ReadDir(s.root, rel)
}

// longEntry formats fi like "ls -l", which every client knows how to parse.
func longEntry(fi fs.FileInfo, now time.Time) string {
	kind := "-"
	switch {
	case fi.IsDir():
		kind = "d"
	case fi.Mode()&fs.ModeSymlink != 0:
		kind = "l"
	}
	t := fi.ModTime()
	stamp := t.Format("Jan _2 15:04")
	if now.Sub(t) > 180*24*time.Hour || t.After(now) {
		stamp = t.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s%s 1 ftp ftp %13d %s %s\r\n", kind, fi.Mode().Perm().String()[1:], fi.Size(), stamp, fi.Name())
}

// mlstFacts are the RFC 3659 facts we send in MLSD and MLST.
const mlstFacts = "type;size;modify;perm;UNIX.mode;"

// timeFormat is the UTC timestamp format of MDTM, MFMT and the modify fact.
const timeFormat = "20060102150405"

func (s *session) mlsd(arg string) {
	_, rel := s.resolve(arg)
	if fi, err := s.root.Stat(rel); err != nil {
		s.fail(arg, err)
		return
	} else if !fi.IsDir() {
		s.reply(501, "%s is not a directory", arg)
		return
	}
	s.sendListing(arg, func(fi fs.FileInfo) string { return s.facts(fi) + " " + fi.Name() + "\r\n" })
}

func (s *session) mlst(arg string) {
	abs, rel := s.resolve(arg)
	fi, err := s.root.Stat(rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	s.replyLines(250, "Listing "+abs, " "+s.facts(fi)+" "+abs, "End.")
}

// facts formats fi as RFC 3659 facts. perm lists what this user may do:
// retrieve, enter and list for everyone; the rest only when not read-only.
func (s *session) facts(fi fs.FileInfo) string {
	typ, size, perm, writePerm := "file", fmt.Sprintf("size=%d;", fi.Size()), "r", "dfw"
	if fi.IsDir() {
		typ, size, perm, writePerm = "dir", "", "el", "cdfmp" // size is for files only
	}
	if !s.readOnly {
		perm += writePerm
	}
	return fmt.Sprintf("type=%s;%smodify=%s;perm=%s;UNIX.mode=%04o;",
		typ, size, fi.ModTime().UTC().Format(timeFormat), perm, fi.Mode().Perm())
}

func (s *session) size(arg string) {
	_, rel := s.resolve(arg)
	fi, err := s.root.Stat(rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	if fi.IsDir() {
		s.reply(550, "%s is a directory", arg)
		return
	}
	s.reply(213, "%d", fi.Size())
}

// avbl reports the free space for uploads in a directory, in bytes
// (draft-peterson-streamlined-ftp-command-extensions).
func (s *session) avbl(arg string) {
	_, rel := s.resolve(arg)
	if fi, err := s.root.Stat(rel); err != nil {
		s.fail(arg, err)
		return
	} else if !fi.IsDir() {
		s.reply(550, "%s is not a directory", arg)
		return
	}
	free, err := jail.Free(s.root, rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	s.reply(213, "%d", free)
}

func (s *session) mdtm(arg string) {
	_, rel := s.resolve(arg)
	fi, err := s.root.Stat(rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	s.reply(213, "%s", fi.ModTime().UTC().Format(timeFormat))
}

// mfmt sets a file's modification time, so clients can keep timestamps on
// upload: MFMT YYYYMMDDHHMMSS <file>, in UTC.
func (s *session) mfmt(arg string) {
	stamp, name, _ := strings.Cut(arg, " ")
	stamp, _, _ = strings.Cut(stamp, ".") // ignore fractional seconds
	t, err := time.Parse(timeFormat, stamp)
	if err != nil || name == "" {
		s.reply(501, "Usage: MFMT YYYYMMDDHHMMSS <file>")
		return
	}
	_, rel := s.resolve(name)
	if err := s.root.Chtimes(rel, t, t); err != nil {
		s.fail(name, err)
		return
	}
	s.reply(213, "Modify=%s; %s", stamp, name)
}

func (s *session) rest(arg string) {
	n, err := strconv.ParseInt(arg, 10, 64)
	if err != nil || n < 0 {
		s.reply(501, "Invalid offset")
		return
	}
	s.offset = n
	s.reply(350, "Restarting at %d", n)
}

// openRegular opens arg for reading, replying with an error unless it's a
// regular file.
func (s *session) openRegular(arg string) (*os.File, bool) {
	_, rel := s.resolve(arg)
	f, err := jail.Open(s.root, rel)
	if err != nil {
		s.fail(arg, err)
		return nil, false
	}
	return f, true
}

func (s *session) retr(arg string) {
	abs, _ := s.resolve(arg)
	f, ok := s.openRegular(arg)
	if !ok {
		return
	}
	defer f.Close()
	if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
		s.fail(arg, err)
		return
	}

	start := time.Now()
	n, ok := s.transfer(func(c net.Conn) (int64, error) { return io.Copy(c, f) })
	s.down += n
	s.log.Info("download", "file", abs, "bytes", n, "ok", ok)
	if ok {
		s.transferred(n, time.Since(start))
	}
}

func (s *session) stor(arg string) {
	abs, rel := s.resolve(arg)
	start := time.Now()
	n, ok := s.transfer(func(c net.Conn) (int64, error) {
		// Open and truncate only once the client has connected, so a failed
		// connection leaves no new file behind and an existing one intact.
		f, err := jail.Create(s.root, rel)
		if err != nil {
			return 0, err
		}
		defer f.Close() // after an error; the Close below reports the normal case
		// Restarting past the end would grow the file to any size.
		if fi, err := f.Stat(); err != nil {
			return 0, err
		} else if s.offset > fi.Size() {
			return 0, errors.New("restart offset is past the end of the file")
		}
		if err := f.Truncate(s.offset); err != nil {
			return 0, err
		}
		if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
			return 0, err
		}
		// Hiding ReadFrom and WriteTo makes CopyBuffer use our 1 MiB buffer
		// instead of a 32 KiB one: fewer, larger disk writes.
		n, err := io.CopyBuffer(struct{ io.Writer }{f}, struct{ io.Reader }{c}, make([]byte, 1<<20))
		return n, errors.Join(err, f.Close())
	})
	s.up += n
	s.log.Info("upload", "file", abs, "bytes", n, "ok", ok)
	if ok {
		s.transferred(n, time.Since(start))
	}
}

func (s *session) dele(arg string) { s.remove(arg, false) }
func (s *session) rmd(arg string)  { s.remove(arg, true) }

// remove deletes a file (DELE) or an empty directory (RMD).
func (s *session) remove(arg string, dir bool) {
	abs, rel := s.resolve(arg)
	fi, err := s.root.Lstat(rel)
	if err != nil {
		s.fail(arg, err)
		return
	}
	if fi.IsDir() != dir {
		want := "a file"
		if dir {
			want = "a directory"
		}
		s.reply(550, "%s is not %s", arg, want)
		return
	}
	if err := s.logged(s.root.Remove(rel), "delete", "path", abs); err != nil {
		s.fail(arg, err)
		return
	}
	s.reply(250, "Deleted %s", arg)
}

func (s *session) mkd(arg string) {
	abs, rel := s.resolve(arg)
	if err := s.logged(jail.Mkdir(s.root, rel), "mkdir", "folder", abs); err != nil {
		s.fail(arg, err)
		return
	}
	s.reply(257, "%s : The directory was successfully created", quote(abs))
}

func (s *session) rnfr(arg string) {
	_, rel := s.resolve(arg)
	if _, err := s.root.Lstat(rel); err != nil {
		s.fail(arg, err)
		return
	}
	s.renaming = rel
	s.reply(350, "RNFR accepted - file exists, ready for destination")
}

func (s *session) rnto(arg string) {
	if s.renaming == "" {
		s.reply(503, "Need RNFR before RNTO")
		return
	}
	abs, rel := s.resolve(arg)
	if err := s.logged(s.root.Rename(s.renaming, rel), "rename", "from", path.Join("/", s.renaming), "to", abs); err != nil {
		s.fail(arg, err)
		return
	}
	s.reply(250, "File successfully renamed or moved")
}

// site handles SITE CHMOD <mode> <file>, the only SITE command we support.
func (s *session) site(arg string) {
	sub, rest, _ := strings.Cut(arg, " ")
	if !strings.EqualFold(sub, "CHMOD") {
		s.reply(500, "SITE: Unknown command")
		return
	}
	modeArg, name, _ := strings.Cut(rest, " ")
	mode, err := strconv.ParseUint(modeArg, 8, 32)
	if err != nil || mode > 0o777 || name == "" {
		s.reply(501, "Usage: SITE CHMOD <mode> <file>")
		return
	}
	abs, rel := s.resolve(name)
	if err := s.logged(s.root.Chmod(rel, fs.FileMode(mode)), "chmod", "path", abs, "mode", fmt.Sprintf("%03o", mode)); err != nil {
		s.fail(name, err)
		return
	}
	s.reply(200, "Permissions changed on %s", name)
}

// quote wraps an FTP path in double quotes, doubling any inside it (RFC 959).
func quote(p string) string {
	return `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
}
