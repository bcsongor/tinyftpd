package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"
)

// A failed certificate write must not strand a new key next to the old
// certificate.
func TestWriteCertPairRollback(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		oldKey := []byte("old key")
		must(t, os.WriteFile(keyPath, oldKey, 0o600))
		must(t, os.Mkdir(certPath, 0o700)) // renaming a file over a directory fails

		if err := writeCertPair(certPath, keyPath, []byte("new cert"), []byte("new key")); err == nil {
			t.Fatal("want a certificate write error")
		}
		got, err := os.ReadFile(keyPath)
		must(t, err)
		if !bytes.Equal(got, oldKey) {
			t.Error("old key was not restored")
		}
	})

	t.Run("no previous key", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		must(t, os.Mkdir(certPath, 0o700))

		if err := writeCertPair(certPath, keyPath, []byte("new cert"), []byte("new key")); err == nil {
			t.Fatal("want a certificate write error")
		}
		if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
			t.Errorf("new key was left behind: %v", err)
		}
	})
}

func TestSelfSign(t *testing.T) {
	dir := t.TempDir()
	// A stale key file with a loose mode must end up private.
	must(t, os.WriteFile(filepath.Join(dir, selfSignedKey), nil, 0o644))

	certPath, keyPath, cert, err := selfSign(dir)
	must(t, err)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(t, err)
	if !bytes.Equal(pair.Leaf.Raw, cert.Raw) {
		t.Fatal("returned certificate differs from the file")
	}

	if got := cert.Subject.Organization; !slices.Equal(got, []string{"Tiny-FTPd"}) {
		t.Errorf("organisation %q", got)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage %v, want digitalSignature only", cert.KeyUsage)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("extended key usage %v, want serverAuth only", cert.ExtKeyUsage)
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		t.Error("want basic constraints CA:FALSE")
	}
	if len(cert.SubjectKeyId) == 0 || !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
		t.Error("want matching subject and authority key identifiers")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm %v", cert.SignatureAlgorithm)
	}
	if got, want := cert.NotAfter.Sub(cert.NotBefore), selfSignedDays*24*time.Hour; got != want {
		t.Errorf("valid for %v, want exactly %v", got, want)
	}
	if cert.SerialNumber.Sign() <= 0 {
		t.Error("serial number must be positive")
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Error(err)
	}

	// It must verify as its own trust anchor, as clients that trust it will.
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	opts := x509.VerifyOptions{Roots: roots, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: time.Now()}
	if _, err := cert.Verify(opts); err != nil {
		t.Error(err)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(keyPath)
		must(t, err)
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("key file mode %v, want 600", got)
		}
	}
	if got := certFingerprint(cert.Raw); len(got) != 32*3-1 {
		t.Errorf("fingerprint %q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
