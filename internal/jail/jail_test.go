package jail

import (
	"os"
	"testing"
)

func TestResolve(t *testing.T) {
	for _, tc := range []struct{ dir, p, abs, rel string }{
		{"/", "", "/", "."},
		{"/a", "b", "/a/b", "a/b"},
		{"/a", "/c", "/c", "c"},
		{"/a", "../../..", "/", "."},
		{"/a/b", "../c/./d", "/a/c/d", "a/c/d"},
	} {
		if abs, rel := Resolve(tc.dir, tc.p); abs != tc.abs || rel != tc.rel {
			t.Errorf("Resolve(%q, %q) = %q, %q; want %q, %q", tc.dir, tc.p, abs, rel, tc.abs, tc.rel)
		}
	}
}

func TestFree(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if free, err := Free(root, "."); err != nil || free == 0 {
		t.Fatalf("Free = %d, %v", free, err)
	}
}
