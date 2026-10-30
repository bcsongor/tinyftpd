package main

import (
	"fmt"
	"slices"
	"testing"
)

func TestLogBuffer(t *testing.T) {
	var b logBuffer
	for i := range logLines + 5 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	lines, total := b.since(0)
	if len(lines) != logLines || lines[0] != "line 5" || total != logLines+5 {
		t.Fatalf("got %d lines starting %q, total %d", len(lines), lines[0], total)
	}

	fmt.Fprint(&b, "a\nb\n")
	if lines, _ := b.since(total); !slices.Equal(lines, []string{"a", "b"}) {
		t.Fatalf("new lines: %q", lines)
	}
}
