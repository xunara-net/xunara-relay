package relay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// serveTestVeil starts a Veil server on an ephemeral port and returns its
// base URL and a shutdown function.
func serveTestVeil(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}
	cfg.Logger = testLogger()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("veil.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("veil.Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("veil.Serve did not stop")
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := srv.Addr(); addr != nil {
			return srv, "http://" + addr.String() + "/derp"
		}
		if time.Now().After(deadline) {
			t.Fatal("veil did not bind a listener")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNodeKeyPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	first, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: dir, Logger: testLogger()})
	if err != nil {
		t.Fatalf("veil.New: %v", err)
	}
	second, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: dir, Logger: testLogger()})
	if err != nil {
		t.Fatalf("veil.New (restart): %v", err)
	}
	if first.PublicKey() != second.PublicKey() {
		t.Fatalf("public key changed across restarts: %v != %v", first.PublicKey(), second.PublicKey())
	}

	fi, err := os.Stat(filepath.Join(dir, "derp.key"))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", perm)
	}
}

func TestDERPMap(t *testing.T) {
	srv, err := New(Config{
		ListenAddr: "0.0.0.0:3340",
		HostName:   "derp.example.com",
		StateDir:   t.TempDir(),
		STUN:       true,
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatalf("veil.New: %v", err)
	}

	m, err := srv.DERPMap()
	if err != nil {
		t.Fatalf("DERPMap: %v", err)
	}
	if !m.OmitDefaultRegions {
		t.Error("OmitDefaultRegions = false, want true")
	}
	region := m.Regions[DefaultRegionID]
	if region == nil {
		t.Fatalf("region %d missing from map", DefaultRegionID)
	}
	if len(region.Nodes) != 1 {
		t.Fatalf("region has %d nodes, want 1", len(region.Nodes))
	}
	node := region.Nodes[0]
	if node.HostName != "derp.example.com" {
		t.Errorf("HostName = %q", node.HostName)
	}
	if node.DERPPort != 3340 {
		t.Errorf("DERPPort = %d, want 3340", node.DERPPort)
	}
	if node.STUNPort != DefaultSTUNPort {
		t.Errorf("STUNPort = %d, want %d", node.STUNPort, DefaultSTUNPort)
	}
	if node.InsecureForTests {
		t.Error("InsecureForTests = true, want false")
	}

	// STUN disabled: the map must tell clients there is no STUN endpoint.
	srv, err = New(Config{
		ListenAddr: "0.0.0.0:3340",
		HostName:   "derp.example.com",
		StateDir:   t.TempDir(),
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatalf("veil.New: %v", err)
	}
	m, err = srv.DERPMap()
	if err != nil {
		t.Fatalf("DERPMap: %v", err)
	}
	if got := m.Regions[DefaultRegionID].Nodes[0].STUNPort; got != -1 {
		t.Errorf("STUNPort with STUN disabled = %d, want -1", got)
	}
}

func TestDERPMapRequiresHostName(t *testing.T) {
	srv, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), Logger: testLogger()})
	if err != nil {
		t.Fatalf("veil.New: %v", err)
	}
	if _, err := srv.DERPMap(); err == nil {
		t.Fatal("DERPMap succeeded without HostName, want error")
	}
}

// dialVeil connects a DERP client to url and returns it.
func dialVeil(t *testing.T, ctx context.Context, url string) *derphttp.Client {
	t.Helper()

	c, err := derphttp.NewClient(key.NewNode(), url, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connecting DERP client: %v", err)
	}

	// The server info frame arrives only after the server admitted and
	// registered the client, so waiting for it makes the client a valid
	// relay target for the tests that follow.
	info := make(chan error, 1)
	go func() {
		for {
			msg, err := c.Recv()
			if err != nil {
				info <- err
				return
			}
			if _, ok := msg.(derp.ServerInfoMessage); ok {
				info <- nil
				return
			}
		}
	}()
	select {
	case err := <-info:
		if err != nil {
			t.Fatalf("waiting for server info: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server info frame")
	}
	return c
}

func TestRelayBetweenClients(t *testing.T) {
	_, url := serveTestVeil(t, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alice := dialVeil(t, ctx, url)
	bob := dialVeil(t, ctx, url)

	want := []byte("hello from alice")
	if err := alice.Send(bob.SelfPublicKey(), want); err != nil {
		t.Fatalf("send: %v", err)
	}

	type recvResult struct {
		msg derp.ReceivedMessage
		err error
	}
	recv := make(chan recvResult, 1)
	go func() {
		// The first server message is the server info frame; keep reading
		// until the relayed packet shows up.
		for {
			msg, err := bob.Recv()
			if err != nil {
				recv <- recvResult{nil, err}
				return
			}
			if _, ok := msg.(derp.ServerInfoMessage); ok {
				continue
			}
			recv <- recvResult{msg, nil}
			return
		}
	}()

	select {
	case res := <-recv:
		if res.err != nil {
			t.Fatalf("recv: %v", res.err)
		}
		pkt, ok := res.msg.(derp.ReceivedPacket)
		if !ok {
			t.Fatalf("received message type %T, want derp.ReceivedPacket", res.msg)
		}
		if pkt.Source != alice.SelfPublicKey() {
			t.Errorf("packet source = %v, want %v", pkt.Source, alice.SelfPublicKey())
		}
		if string(pkt.Data) != string(want) {
			t.Errorf("packet data = %q, want %q", pkt.Data, want)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for relayed packet")
	}
}

// fakeAdmission is a test admission controller.
func fakeAdmission(t *testing.T, allow bool) (*httptest.Server, <-chan tailcfg.DERPAdmitClientRequest) {
	t.Helper()

	requests := make(chan tailcfg.DERPAdmitClientRequest, 8)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("admission method = %s, want POST", r.Method)
		}
		var req tailcfg.DERPAdmitClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decoding admission request: %v", err)
		}
		requests <- req
		json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow})
	}))
	t.Cleanup(hs.Close)
	return hs, requests
}

func TestAdmissionControllerAllows(t *testing.T) {
	admission, requests := fakeAdmission(t, true)
	_, url := serveTestVeil(t, Config{VerifyURL: admission.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := dialVeil(t, ctx, url)

	select {
	case req := <-requests:
		if req.NodePublic != client.SelfPublicKey() {
			t.Errorf("admission NodePublic = %v, want %v", req.NodePublic, client.SelfPublicKey())
		}
		if !req.Source.IsValid() {
			t.Error("admission Source is not a valid address")
		}
	case <-ctx.Done():
		t.Fatal("admission controller was not called")
	}
}

func TestAdmissionControllerDenies(t *testing.T) {
	admission, _ := fakeAdmission(t, false)
	_, url := serveTestVeil(t, Config{VerifyURL: admission.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := derphttp.NewClient(key.NewNode(), url, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		// Some failures surface already at connect time.
		return
	}
	// derphttp connects lazily, so the rejection may only surface as the
	// server hanging up on the first read.
	assertServerRejects(t, ctx, c)
}

// assertServerRejects requires that reading from a client fails (the server
// hung up), rather than returning a message from an admitted session.
func assertServerRejects(t *testing.T, ctx context.Context, c *derphttp.Client) {
	t.Helper()

	type recvResult struct {
		msg derp.ReceivedMessage
		err error
	}
	recv := make(chan recvResult, 1)
	go func() {
		msg, err := c.Recv()
		recv <- recvResult{msg, err}
	}()

	select {
	case res := <-recv:
		if res.err == nil {
			t.Fatalf("client received %T from a session that should have been rejected", res.msg)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the server to reject the client")
	}
}

// TestAdmissionControllerUnreachableFailsClosed pins the fail-closed
// behaviour: with the admission controller down, no client connects.
func TestAdmissionControllerUnreachableFailsClosed(t *testing.T) {
	admission, _ := fakeAdmission(t, true)
	admission.Close() // now unreachable

	_, url := serveTestVeil(t, Config{VerifyURL: admission.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := derphttp.NewClient(key.NewNode(), url, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		return
	}
	assertServerRejects(t, ctx, c)
}

// TestProbeEndpoints covers the latency probe endpoints netcheck and the
// browser client rely on.
func TestProbeEndpoints(t *testing.T) {
	_, url := serveTestVeil(t, Config{})
	base := url[:len(url)-len("/derp")]

	for _, path := range []string{"/derp/probe", "/derp/latency-check"} {
		resp, err := http.Head(base + path)
		if err != nil {
			t.Fatalf("HEAD %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("HEAD %s status = %d, want 200", path, resp.StatusCode)
		}
	}
}
