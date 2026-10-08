package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// TestCertModeValidation pins the fail-closed configuration rules for TLS
// certificate modes.
func TestCertModeValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cfg     Config
		wantErr string
		wantTLS bool
	}{
		{
			name: "no TLS",
			cfg:  Config{},
		},
		{
			name:    "manual files",
			cfg:     Config{CertFile: "cert.pem", CertKeyFile: "key.pem"},
			wantTLS: true,
		},
		{
			name:    "manual mode requires both files",
			cfg:     Config{CertMode: CertModeManual, CertFile: "cert.pem"},
			wantErr: "requires both CertFile and CertKeyFile",
		},
		{
			name:    "manual mode supports the explicit form",
			cfg:     Config{CertMode: CertModeManual, CertFile: "cert.pem", CertKeyFile: "key.pem"},
			wantTLS: true,
		},
		{
			name:    "letsencrypt needs a cache directory",
			cfg:     Config{CertMode: CertModeLetsEncrypt, HostName: "derp.example.com"},
			wantErr: "requires CertDir",
		},
		{
			name:    "letsencrypt refuses certificate files",
			cfg:     Config{CertMode: CertModeLetsEncrypt, HostName: "derp.example.com", CertDir: t.TempDir(), CertFile: "cert.pem", CertKeyFile: "key.pem"},
			wantErr: "cannot be combined with CertFile",
		},
		{
			name:    "letsencrypt needs a hostname",
			cfg:     Config{CertMode: CertModeLetsEncrypt, CertDir: t.TempDir()},
			wantErr: "requires HostName",
		},
		{
			name:    "letsencrypt rejects an IP hostname",
			cfg:     Config{CertMode: CertModeLetsEncrypt, HostName: "203.0.113.7", CertDir: t.TempDir()},
			wantErr: "not an IP address",
		},
		{
			name:    "letsencrypt requires a fully qualified name",
			cfg:     Config{CertMode: CertModeLetsEncrypt, HostName: "relay", CertDir: t.TempDir()},
			wantErr: "fully qualified",
		},
		{
			name:    "letsencrypt rejects a port",
			cfg:     Config{CertMode: CertModeLetsEncrypt, HostName: "derp.example.com:3340", CertDir: t.TempDir()},
			wantErr: "not a valid DNS name",
		},
		{
			name:    "selfsigned needs a hostname",
			cfg:     Config{CertMode: CertModeSelfSigned, CertDir: t.TempDir()},
			wantErr: "requires HostName",
		},
		{
			name:    "selfsigned refuses certificate files",
			cfg:     Config{CertMode: CertModeSelfSigned, HostName: "203.0.113.7", CertFile: "cert.pem", CertKeyFile: "key.pem"},
			wantErr: "cannot be combined with CertFile",
		},
		{
			name:    "unknown mode",
			cfg:     Config{CertMode: "acme-http"},
			wantErr: "unsupported CertMode",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.ListenAddr = "127.0.0.1:0"
			cfg.StateDir = t.TempDir()
			cfg.Logger = testLogger()
			srv, err := New(cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := srv.cfg.TLS(); got != tt.wantTLS {
				t.Errorf("TLS() = %v, want %v", got, tt.wantTLS)
			}
			if (srv.acme != nil) != (tt.cfg.CertMode == CertModeLetsEncrypt && tt.cfg.CertFile == "") {
				t.Errorf("acme manager = %v, want %v", srv.acme != nil, tt.cfg.CertMode == CertModeLetsEncrypt)
			}
		})
	}
}

// TestACMEHostPolicy checks the automatic certificate source only serves the
// configured name and wires the TLS-ALPN-01 challenge.
func TestACMEHostPolicy(t *testing.T) {
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		StateDir:   t.TempDir(),
		HostName:   "Derp.Example.com",
		CertMode:   CertModeLetsEncrypt,
		CertDir:    t.TempDir(),
		Logger:     testLogger(),
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.acme == nil {
		t.Fatal("no ACME manager configured")
	}

	tlsCfg := srv.acme.TLSConfig()
	if !slices.Contains(tlsCfg.NextProtos, acme.ALPNProto) {
		t.Errorf("NextProtos = %v, want %s for the TLS-ALPN-01 challenge", tlsCfg.NextProtos, acme.ALPNProto)
	}
	if !slices.Contains(tlsCfg.NextProtos, "http/1.1") {
		t.Errorf("NextProtos = %v, want http/1.1 for the DERP upgrade", tlsCfg.NextProtos)
	}

	for _, tt := range []struct {
		name string
		sni  string
	}{
		{"empty SNI", ""},
		{"other host", "evil.example.com"},
		{"parent domain", "example.com"},
	} {
		_, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: tt.sni})
		if err == nil {
			t.Errorf("%s: GetCertificate accepted SNI %q", tt.name, tt.sni)
		}
	}
}

// TestACMECachedCertificateIsServed seeds the ACME cache with a certificate
// for the configured host and checks the manager serves it without any
// network round trip: this is the path a restarted deployment takes.
func TestACMECachedCertificateIsServed(t *testing.T) {
	const host = "derp.example.com"
	certDir := t.TempDir()
	certPEM, keyPEM := selfSignedCert(t, host, 90*24*time.Hour)
	if err := os.WriteFile(filepath.Join(certDir, host), append(keyPEM, certPEM...), 0o600); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		StateDir:   t.TempDir(),
		HostName:   host,
		CertMode:   CertModeLetsEncrypt,
		CertDir:    certDir,
		Logger:     testLogger(),
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := srv.acme.TLSConfig().GetCertificate(&tls.ClientHelloInfo{
		ServerName: host,
		// Pin ECDSA cipher suites and schemes so the cache key has no
		// "+rsa" suffix, matching the seeded file. autocert keys RSA
		// clients separately unless the hello proves ECDSA support.
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.Leaf == nil {
		t.Fatal("served certificate has no parsed leaf")
	}
	if err := got.Leaf.VerifyHostname(host); err != nil {
		t.Errorf("served certificate does not match the host: %v", err)
	}
}

// TestManualTLSListener serves DERP over manually supplied certificate files,
// covering the explicit manual mode end to end.
func TestManualTLSListener(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedCert(t, "127.0.0.1", 24*time.Hour)
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	srv, _ := serveTestVeil(t, Config{
		CertMode:    CertModeManual,
		CertFile:    certFile,
		CertKeyFile: keyFile,
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Head("https://" + srv.Addr().String() + "/derp/probe")
	if err != nil {
		t.Fatalf("HEAD over TLS: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("probe status = %d, want 200", resp.StatusCode)
	}
}

// selfSignedCert returns a PEM certificate and key for host, valid for
// validFor.
func selfSignedCert(t *testing.T, host string, validFor time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
