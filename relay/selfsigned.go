package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Self-signed certificates exist for deployments that cannot obtain a public
// certificate: a relay reached by IP address, behind CGNAT/provider NAT, with
// no DNS name to validate. The official DERP client still requires TLS on the
// relay connection, so Veil generates a key pair, serves it, and publishes the
// SHA-256 pin of the certificate in the DERP map ("sha256-raw:" in
// tailcfg.DERPNode.CertName, the upstream mechanism for exactly this case).
// Pinning replaces CA validation for that node, and nothing else: the pin only
// ever appears in a map the control plane serves to its own tailnet.
const (
	// CertModeSelfSigned makes Veil generate and serve its own certificate.
	CertModeSelfSigned = "selfsigned"

	// selfSignedCertName and selfSignedKeyName are the file names inside the
	// certificate directory. The key is written 0600 (AGENTS.md section 8).
	selfSignedCertName = "selfsigned.crt"
	selfSignedKeyName  = "selfsigned.key"

	// selfSignedValidity is how long a generated certificate lasts. It is
	// deliberately long: rotating it changes the published pin, and clients
	// only accept the new pin after their next netmap update.
	selfSignedValidity = 825 * 24 * time.Hour

	// selfSignedRenewBefore regenerates a certificate that is about to
	// expire, so a restart well before the deadline never serves a stale one.
	selfSignedRenewBefore = 30 * 24 * time.Hour
)

// selfSignedCertDir returns the directory holding the generated pair.
func (c Config) selfSignedCertDir() string {
	if c.CertDir != "" {
		return c.CertDir
	}
	if c.StateDir != "" {
		return c.StateDir
	}
	return "."
}

// selfSignedHost validates the name the certificate is issued for. Either a
// DNS name (matched by SNI) or an IP literal (matched by IP SAN).
func (c Config) selfSignedHost() (string, error) {
	host := strings.ToLower(strings.TrimSpace(c.HostName))
	if host == "" {
		return "", errors.New("veil: CertMode selfsigned requires HostName (the name or address clients dial)")
	}
	if strings.ContainsAny(host, " :/\t\r\n") {
		return "", fmt.Errorf("veil: HostName %q is not usable as a certificate name", c.HostName)
	}
	return host, nil
}

// certSHA256Pin renders the "sha256-raw:" pin the DERP map carries.
func certSHA256Pin(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256-raw:" + hex.EncodeToString(sum[:])
}

// loadOrCreateSelfSignedCert returns the certificate to serve together with
// its pin. An existing pair is reused while it still covers the host and is
// not near expiry, so restarts do not churn the published pin.
func loadOrCreateSelfSignedCert(dir, host string, log *slog.Logger) (tls.Certificate, string, error) {
	certPath := filepath.Join(dir, selfSignedCertName)
	keyPath := filepath.Join(dir, selfSignedKeyName)

	if cert, der, ok := readSelfSignedPair(certPath, keyPath, host); ok {
		return cert, certSHA256Pin(der), nil
	}

	certPEM, keyPEM, der, err := generateSelfSignedCert(host)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("veil: creating certificate directory: %w", err)
	}
	// The key is written first and the certificate second: a crash in between
	// leaves a pair that the next start regenerates, never a certificate
	// without its key.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("veil: writing %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("veil: writing %s: %w", certPath, err)
	}
	log.Info("veil generated a self-signed certificate",
		"host", host, "cert", certPath, "pin", certSHA256Pin(der))

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("veil: loading the generated certificate: %w", err)
	}
	return cert, certSHA256Pin(der), nil
}

// readSelfSignedPair loads an existing pair when it is still usable for host.
func readSelfSignedPair(certPath, keyPath, host string) (tls.Certificate, []byte, bool) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, nil, false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, false
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, nil, false
	}
	der := cert.Certificate[0]
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, false
	}
	now := time.Now()
	switch {
	case now.After(leaf.NotAfter.Add(-selfSignedRenewBefore)):
		return tls.Certificate{}, nil, false
	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, nil, false
	case !coversHost(leaf, host):
		return tls.Certificate{}, nil, false
	}
	return cert, der, true
}

// coversHost reports whether the certificate is valid for the name clients
// dial with.
func coversHost(leaf *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, have := range leaf.IPAddresses {
			if have.Equal(ip) {
				return true
			}
		}
		return false
	}
	return leaf.VerifyHostname(host) == nil
}

// generateSelfSignedCert builds a fresh key pair for host.
func generateSelfSignedCert(host string) (certPEM, keyPEM, der []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("veil: generating the certificate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("veil: generating the certificate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("veil: signing the certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("veil: encoding the certificate key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if certPEM == nil || keyPEM == nil {
		return nil, nil, nil, errors.New("veil: encoding the certificate failed")
	}
	return certPEM, keyPEM, der, nil
}
