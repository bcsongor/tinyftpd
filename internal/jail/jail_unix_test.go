//go:build unix

package jail

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Opening a FIFO would wait for its other end, so Open and Create must
// refuse it without blocking.
func TestRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	for name, open := range map[string]func(*os.Root, string) (*os.File, error){"Open": Open, "Create": Create} {
		done := make(chan error, 1)
		go func() {
			f, err := open(root, "fifo")
			if err == nil {
				f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s opened a FIFO", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s blocked on a FIFO", name)
		}
	}
}
