package relay

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// freePort reserves a TCP port for a server whose DERP map must advertise the
// real port (a :0 listener would publish the default 443 instead).
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// selfSignedConfig builds a usable self-signed server configuration.
func selfSignedConfig(t *testing.T, host, certDir string) Config {
	t.Helper()

	return Config{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		HostName:   host,
		CertDir:    certDir,
		CertMode:   CertModeSelfSigned,
		STUN:       false,
	}
}

// regionClient dials a server through the same code path official clients
// use: the DERP map entry decides the TLS server name and the certificate
// pin, so connecting proves the published pin is the one the relay serves.
func regionClient(t *testing.T, ctx context.Context, m *tailcfg.DERPMap, region tailcfg.DERPRegionID) (*derphttp.Client, error) {
	t.Helper()

	reg := m.Regions[region]
	if reg == nil {
		t.Fatalf("region %d missing from the DERP map", region)
	}
	c := derphttp.NewRegionClient(key.NewNode(), t.Logf, netmon.NewStatic(),
		func() *tailcfg.DERPRegion { return reg })
	t.Cleanup(func() { c.Close() })
	return c, c.Connect(ctx)
}

func TestSelfSignedRequiresHostName(t *testing.T) {
	_, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), Logger: testLogger(),
		CertMode: CertModeSelfSigned})
	if err == nil {
		t.Fatal("New accepted CertMode selfsigned without a HostName")
	}
}

func TestSelfSignedRejectsManualCertFiles(t *testing.T) {
	_, err := New(Config{ListenAddr: "127.0.0.1:0", HostName: "relay.example.com", StateDir: t.TempDir(),
		Logger: testLogger(), CertMode: CertModeSelfSigned,
		CertFile: "cert.pem", CertKeyFile: "key.pem"})
	if err == nil {
		t.Fatal("New accepted a self-signed mode combined with CertFile/CertKeyFile")
	}
}

// TestSelfSignedServesPinnedCertificate is the interoperability test: a client
// that only knows the DERP map must accept the generated certificate, and a
// client given the wrong pin must refuse it.
func TestSelfSignedServesPinnedCertificate(t *testing.T) {
	ctx := context.Background()
	srv, _ := serveTestVeil(t, selfSignedConfig(t, "127.0.0.1", filepath.Join(t.TempDir(), "certs")))

	m, err := srv.DERPMap()
	if err != nil {
		t.Fatalf("DERPMap: %v", err)
	}
	node := m.Regions[DefaultRegionID].Nodes[0]
	if !strings.HasPrefix(node.CertName, "sha256-raw:") {
		t.Fatalf("CertName = %q, want a sha256-raw pin", node.CertName)
	}
	if got := strings.TrimPrefix(node.CertName, "sha256-raw:"); len(got) != 64 {
		t.Fatalf("pin %q is not a hex SHA-256", node.CertName)
	}

	// The pin must be the hash of the certificate the relay actually serves.
	sum := sha256.Sum256(srv.cert.Certificate[0])
	if want := "sha256-raw:" + hex.EncodeToString(sum[:]); node.CertName != want {
		t.Errorf("published pin = %q, want %q", node.CertName, want)
	}

	if _, err := regionClient(t, ctx, m, DefaultRegionID); err != nil {
		t.Fatalf("pinned client could not connect: %v", err)
	}

	// A client with a different pin must not accept the same relay.
	tampered := *node
	tampered.CertName = "sha256-raw:" + strings.Repeat("11", 32)
	bad := m.Regions[DefaultRegionID]
	badCopy := *bad
	badCopy.Nodes = []*tailcfg.DERPNode{&tampered}
	badMap := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{DefaultRegionID: &badCopy}}
	if _, err := regionClient(t, ctx, badMap, DefaultRegionID); err == nil {
		t.Fatal("a client with the wrong pin connected to the relay")
	}
}

func TestSelfSignedCoversDNSHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	srv, _ := serveTestVeil(t, selfSignedConfig(t, "relay.example.com", dir))

	leaf := parseServedLeaf(t, srv)
	if err := leaf.VerifyHostname("relay.example.com"); err != nil {
		t.Errorf("certificate does not cover its host: %v", err)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Errorf("DNS certificate carries IP SANs: %v", leaf.IPAddresses)
	}
}

func TestSelfSignedReusesPairAcrossRestarts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	first, _ := serveTestVeil(t, selfSignedConfig(t, "127.0.0.1", dir))
	if first.certPin == "" {
		t.Fatal("first server has no pin")
	}

	keyPath := filepath.Join(dir, selfSignedKeyName)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	// A restart on a new port with the same certificate directory must reuse
	// the pair: the published pin may not change under a running tailnet.
	second, _ := serveTestVeil(t, selfSignedConfig(t, "127.0.0.1", dir))
	if second.certPin != first.certPin {
		t.Errorf("restart changed the published pin: %q != %q", second.certPin, first.certPin)
	}
}

func TestSelfSignedRegeneratesForANewHost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	first, _ := serveTestVeil(t, selfSignedConfig(t, "127.0.0.1", dir))
	second, _ := serveTestVeil(t, selfSignedConfig(t, "192.0.2.10", dir))

	if first.certPin == second.certPin {
		t.Error("a certificate for another host was reused")
	}
	leaf := parseServedLeaf(t, second)
	if err := leaf.VerifyHostname("192.0.2.10"); err != nil {
		t.Errorf("regenerated certificate does not cover the new host: %v", err)
	}
}

func parseServedLeaf(t *testing.T, srv *Server) *x509.Certificate {
	t.Helper()

	if srv.cert == nil {
		t.Fatal("server has no self-signed certificate")
	}
	leaf, err := x509.ParseCertificate(srv.cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the served certificate: %v", err)
	}
	return leaf
}
