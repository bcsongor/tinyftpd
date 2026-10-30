package ftp

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"hash/crc32"
	"io"
	"slices"
	"strings"
)

type checksumAlgo struct {
	name string
	new  func() hash.Hash
}

// hashAlgos are the checksums HASH and the X* commands offer, in FEAT order.
var hashAlgos = []checksumAlgo{
	{"SHA-1", sha1.New},
	{"SHA-256", sha256.New},
	{"SHA-512", sha512.New},
	{"MD5", md5.New},
	{"CRC32", func() hash.Hash { return crc32.NewIEEE() }},
}

func findHash(name string) (func() hash.Hash, bool) {
	i := slices.IndexFunc(hashAlgos, func(a checksumAlgo) bool { return strings.EqualFold(a.name, name) })
	if i < 0 {
		return nil, false
	}
	return hashAlgos[i].new, true
}

// hashList is the FEAT value for HASH, with the selected algorithm starred.
func (s *session) hashList() string {
	names := make([]string, len(hashAlgos))
	for i, a := range hashAlgos {
		names[i] = a.name
		if a.name == s.hashAlgo {
			names[i] += "*"
		}
	}
	return strings.Join(names, ";")
}

// optsHash handles OPTS HASH, which shows or selects the HASH algorithm.
func (s *session) optsHash(name string) {
	if name == "" {
		s.reply(200, "%s", s.hashAlgo)
		return
	}
	if _, ok := findHash(name); !ok {
		s.reply(501, "Unknown algorithm, choose from %s", strings.ReplaceAll(s.hashList(), "*", ""))
		return
	}
	s.hashAlgo = strings.ToUpper(name)
	s.reply(200, "%s", s.hashAlgo)
}

// hash implements HASH <file> (draft-bryan-ftpext-hash) for the whole file.
func (s *session) hash(arg string) {
	newHash, _ := findHash(s.hashAlgo)
	if sum, n, ok := s.checksum(arg, newHash); ok {
		s.reply(213, "%s 0-%d %s %s", s.hashAlgo, n, sum, arg)
	}
}

// xhash returns a handler for the older XCRC, XMD5 and XSHA* commands.
func xhash(algo string) func(*session, string) {
	newHash, _ := findHash(algo)
	return func(s *session, arg string) {
		if sum, _, ok := s.checksum(arg, newHash); ok {
			s.reply(250, "%s", sum)
		}
	}
}

// checksum hashes the regular file arg, returning its hex digest and size.
func (s *session) checksum(arg string, newHash func() hash.Hash) (string, int64, bool) {
	f, ok := s.openRegular(arg)
	if !ok {
		return "", 0, false
	}
	defer f.Close()
	h := newHash()
	n, err := io.Copy(h, ctxReader{s.ctx, f})
	if err != nil {
		s.fail(arg, err)
		return "", 0, false
	}
	return hex.EncodeToString(h.Sum(nil)), n, true
}

// ctxReader stops reading once ctx is done, so hashing a large file doesn't
// hold up shutdown.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
