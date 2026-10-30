package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Self-signed certificate files, kept next to the config.
const selfSignedCert, selfSignedKey = "tinyftpd-cert.pem", "tinyftpd-key.pem"

// selfSignedDays is the longest validity Apple platforms accept for a TLS
// server certificate; longer ones fail on macOS and iOS clients.
const selfSignedDays = 825

// selfSign writes a new self-signed certificate and key into dir, valid for
// this machine's hostname and addresses. It returns the file paths and the
// certificate itself, whose fingerprint clients show when asked to trust it.
func selfSign(dir string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	tmpl, err := certTemplate(&key.PublicKey)
	if err != nil {
		return "", "", nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	if cert, err = x509.ParseCertificate(der); err != nil {
		return "", "", nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}

	certPath, keyPath = filepath.Join(dir, selfSignedCert), filepath.Join(dir, selfSignedKey)
	if err := writeCertPair(certPath, keyPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyDER); err != nil {
		return "", "", nil, err
	}
	return certPath, keyPath, cert, nil
}

// certTemplate describes a self-signed server certificate for pub with only
// what a TLS server needs: digitalSignature key usage, serverAuth extended
// key usage, CA:FALSE, and key identifiers.
func certTemplate(pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(point) // RFC 5280 section 4.2.1.2, method 1
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}

	host := "localhost"
	if h, err := os.Hostname(); err == nil {
		host = strings.ToLower(h)
	}
	notBefore := time.Now().Add(-time.Hour) // tolerate clock skew
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)), // positive, never zero
		Subject: pkix.Name{
			CommonName:         host,
			Organization:       []string{"Tiny-FTPd"},
			OrganizationalUnit: []string{"Self-signed FTPS certificate"},
		},
		DNSNames:              slices.Compact([]string{host, "localhost"}),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(selfSignedDays * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:], // self-signed: the issuer is itself
	}
	for _, ip := range localIPs() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	return tmpl, nil
}

// writeCertPair writes a certificate chain and PKCS#8 private key. If the
// certificate write fails after the key was replaced, it restores the old key.
// A restoration failure is returned together with the original error.
func writeCertPair(certPath, keyPath string, certPEM, keyDER []byte) error {
	oldKey, readErr := os.ReadFile(keyPath)
	hasOldKey := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		var restoreErr error
		if hasOldKey {
			restoreErr = writeFile(keyPath, oldKey, 0o600)
		} else {
			restoreErr = os.Remove(keyPath)
		}
		return errors.Join(err, restoreErr)
	}
	return nil
}

// checkExpiry warns about a certificate that has expired or soon will.
func checkExpiry(cert *x509.Certificate) {
	switch left := time.Until(cert.NotAfter); {
	case left <= 0:
		slog.Warn("TLS certificate has expired, clients will refuse it", "expired", cert.NotAfter.Format(time.DateOnly))
	case left < 30*24*time.Hour:
		slog.Warn("TLS certificate expires soon", "expires", cert.NotAfter.Format(time.DateOnly))
	}
}

// certFingerprint formats a certificate's SHA-256 hash the way FTP clients
// show it, e.g. "AB:CD:...".
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ReplaceAll(fmt.Sprintf("% X", sum[:]), " ", ":")
}
