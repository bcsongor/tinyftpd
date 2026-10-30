package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetUser(t *testing.T) {
	dir := t.TempDir()
	var c Config

	if err := c.setUser("", User{Name: "a", Root: dir}, ""); err == nil {
		t.Error("added a user without a password")
	}
	if err := c.setUser("", User{Name: "a", Root: filepath.Join(dir, "missing")}, "pw"); err == nil {
		t.Error("added a user with a missing folder")
	}
	if err := c.setUser("", User{Name: "a", Root: " "}, "pw"); err == nil {
		t.Error("added a user with a blank folder") // would resolve to the working directory
	}
	if err := c.setUser("", User{Name: " a ", Root: dir}, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := c.setUser("", User{Name: "a", Root: dir}, "pw"); err == nil {
		t.Error("added a duplicate user")
	}

	// Start folders end up as paths inside the jail.
	must(t, os.MkdirAll(filepath.Join(dir, "photos", "2026"), 0o755))
	for start, want := range map[string]string{
		"":                                   "",
		dir:                                  "",
		filepath.Join(dir, "photos", "2026"): "/photos/2026",
		"photos":                             "/photos",
		"/photos":                            "/photos",
	} {
		if err := c.setUser("a", User{Name: "a", Root: dir, Start: start}, ""); err != nil {
			t.Errorf("start %q: %v", start, err)
		} else if got := c.Users[0].Start; got != want {
			t.Errorf("start %q stored as %q, want %q", start, got, want)
		}
	}
	for _, start := range []string{"..", filepath.Dir(dir), "missing"} {
		if err := c.setUser("a", User{Name: "a", Root: dir, Start: start}, ""); err == nil {
			t.Errorf("accepted start folder %q", start)
		}
	}

	// Renaming with a blank password keeps the old one.
	if err := c.setUser("a", User{Name: "b", Root: dir, ReadOnly: true}, ""); err != nil {
		t.Fatal(err)
	}
	if len(c.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(c.Users))
	}
	if u, ok := c.authenticate("b", "pw"); !ok || !u.ReadOnly {
		t.Errorf("renamed user: ok=%v readOnly=%v", ok, u.ReadOnly)
	}
	// bcrypt would accept "pw" repeated with NULs between copies.
	if _, ok := c.authenticate("b", "pw\x00pw"); ok {
		t.Error("accepted a NUL variant of the password")
	}
}

func TestValidate(t *testing.T) {
	ok := Config{Port: 21, WebPort: 8080, MaxConns: 50}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"port":           func(c *Config) { c.Port = 0 },
		"web port":       func(c *Config) { c.Web, c.WebPort = true, 70000 },
		"same ports":     func(c *Config) { c.Web, c.WebPort = true, 21 },
		"negative limit": func(c *Config) { c.MaxConns = -1 },
		"inverted range": func(c *Config) { c.PasvMin, c.PasvMax = 50010, 50000 },
		"half a range":   func(c *Config) { c.PasvMin = 50000 },
		"listen address": func(c *Config) { c.ListenIP = "localhost" },
		"public address": func(c *Config) { c.PublicIP = "1.2.3" },
	} {
		c := ok
		change(&c)
		if c.validate() == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}

// A start folder that's a symlink out of the jail must be refused when the
// user is saved, since the servers refuse it at login.
func TestStartDirSymlinkEscape(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Skip("can't create symlinks:", err)
	}
	if _, err := startDir(dir, "out"); err == nil {
		t.Error("accepted a start folder that links out of the jail")
	}
}
