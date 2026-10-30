// Package jail is what the FTP and web servers share about users and their
// folders: accounts, login throttling, resolving paths inside a jail,
// permissions for new entries, and free space.
package jail

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Account is what a successful login grants.
type Account struct {
	Root     string // folder the user is jailed to
	Start    string // directory to start in, inside the jail, e.g. "/photos"
	ReadOnly bool
	// BypassLimit lets the user log in when the server is full, without
	// taking up one of its places.
	BypassLimit bool
}

// Auth checks credentials. Servers call it on every login, so user changes
// apply without a restart.
type Auth func(user, password string) (Account, bool)

// Resolve maps p, absolute or relative to dir, to an absolute path inside the
// jail and its os.Root-relative form. path.Clean stops ".." at "/", and
// os.Root blocks symlink escapes.
func Resolve(dir, p string) (abs, rel string) {
	if !strings.HasPrefix(p, "/") {
		p = dir + "/" + p
	}
	abs = path.Clean(p)
	rel = strings.TrimPrefix(abs, "/")
	if rel == "" {
		rel = "."
	}
	return abs, rel
}

// Free returns the bytes available for new files in the directory rel.
func Free(root *os.Root, rel string) (uint64, error) {
	return diskFree(filepath.Join(root.Name(), filepath.FromSlash(rel)))
}

// Mode returns the permissions for a new entry at rel, copied from its parent
// folder: directories take the parent's mode, including setgid so
// shared-group folders keep working, and files drop the execute bits. Windows
// ignores this and inherits ACLs from the parent by itself.
func Mode(root *os.Root, rel string, dir bool) os.FileMode {
	parent, err := root.Stat(path.Dir(rel))
	if err != nil {
		if dir {
			return 0o755
		}
		return 0o644
	}
	if dir {
		return parent.Mode() & (os.ModePerm | os.ModeSetgid)
	}
	return parent.Mode().Perm() &^ 0o111
}

// Mkdir creates the directory rel with its parent's permissions. They're
// applied with Chmod afterwards, so the process umask doesn't interfere and
// setgid survives, which Mkdir itself won't take.
func Mkdir(root *os.Root, rel string) error {
	mode := Mode(root, rel, true)
	if err := root.Mkdir(rel, mode.Perm()); err != nil {
		return err
	}
	root.Chmod(rel, mode) // best effort; the directory exists either way
	return nil
}

// Create opens rel for writing without truncating it, creating it with its
// parent's permissions if it's new. It refuses anything but a regular file.
func Create(root *os.Root, rel string) (*os.File, error) {
	_, statErr := root.Stat(rel)
	mode := Mode(root, rel, false)
	f, err := openRegular(root, rel, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return nil, err
	}
	if errors.Is(statErr, fs.ErrNotExist) {
		f.Chmod(mode) // bypass the umask; leave existing files alone
	}
	return f, nil
}

// Open opens rel for reading, refusing anything but a regular file.
func Open(root *os.Root, rel string) (*os.File, error) {
	return openRegular(root, rel, os.O_RDONLY, 0)
}

// openRegular opens rel and checks what it opened, so the check can't be
// raced by swapping the file. Opening is non-blocking, as a FIFO would
// otherwise wait for its other end.
func openRegular(root *os.Root, rel string, flag int, mode os.FileMode) (*os.File, error) {
	f, err := root.OpenFile(rel, flag|nonBlock, mode)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: rel, Err: errNotRegular}
	}
	return f, nil
}

var errNotRegular = errors.New("not a regular file")

// ReadDir lists the directory rel. Symlinks show as what they point to, under
// the link's name, since clients can't follow them; links out of the jail
// fail to stat and stay links. Entries that vanish meanwhile are left out.
func ReadDir(root *os.Root, rel string) ([]fs.FileInfo, error) {
	entries, err := fs.ReadDir(root.FS(), rel)
	if err != nil {
		return nil, err
	}
	infos := make([]fs.FileInfo, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if target, err := root.Stat(path.Join(rel, e.Name())); err == nil {
				fi = renamed{target, e.Name()}
			}
		}
		infos = append(infos, fi)
	}
	return infos, nil
}

// renamed is a FileInfo under another name: a symlink's target, listed under
// the link's name.
type renamed struct {
	fs.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

// Reason is err's message without the path, which for files opened via
// os.Root is the host path. It's what users see when something fails.
func Reason(err error) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return pe.Err.Error()
	}
	if le, ok := errors.AsType[*os.LinkError](err); ok {
		return le.Err.Error()
	}
	return err.Error()
}
