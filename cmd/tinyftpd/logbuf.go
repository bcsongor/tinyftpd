package main

import (
	"slices"
	"strings"
	"sync"
)

// The GUI keeps the most recent logLines log lines, each cut to
// maxLineLen bytes, so clients can't fill memory through what gets logged.
const (
	logLines   = 1000
	maxLineLen = 1024
)

// logBuffer keeps the most recent log lines in memory for the GUI's log
// window. It's an io.Writer, so the standard logger can write to it.
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	total int // lines ever written; lines holds the most recent ones
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for line := range strings.Lines(string(p)) {
		line = strings.TrimRight(line, "\r\n")
		if len(line) > maxLineLen {
			line = strings.ToValidUTF8(line[:maxLineLen], "") + "..."
		}
		b.lines = append(b.lines, line)
		b.total++
	}
	if extra := len(b.lines) - logLines; extra > 0 {
		b.lines = slices.Delete(b.lines, 0, extra)
	}
	return len(p), nil
}

// since returns the lines written after the first n, and the total to pass
// next time.
func (b *logBuffer) since(n int) ([]string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	skip := max(n-(b.total-len(b.lines)), 0)
	return slices.Clone(b.lines[skip:]), b.total
}
