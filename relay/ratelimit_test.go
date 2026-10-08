package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/derp"
)

// TestLimitedConnThrottles checks that a connection with a small limit actually
// slows down, and that the reserve is the thing doing it.
func TestLimitedConnThrottles(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// 4 KiB/s with a 1 KiB bucket: the first 1 KiB write drains the bucket,
	// and the second has to wait about 250ms for tokens to refill.
	conn := newLimitedConn(server, rate.NewLimiter(rate.Limit(4096), 1024))
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	if _, err := conn.Write(make([]byte, 1024)); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	start := time.Now()
	if _, err := conn.Write(make([]byte, 1024)); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("second write took %v, want it throttled by the limiter", elapsed)
	}
}

// TestLimitedConnCloseUnblocksReserve checks that closing a connection does not
// leave a caller waiting out the remaining tokens.
func TestLimitedConnCloseUnblocksReserve(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	conn := newLimitedConn(server, rate.NewLimiter(rate.Limit(1), 1))
	if err := conn.reserve(1); err != nil {
		t.Fatalf("first reserve: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- conn.reserve(1) }()

	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("reserve after close = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve did not unblock after Close")
	}
}

// TestMeshKeyValidation covers the configuration rules for the DERP mesh key:
// a valid key enables meshing, a malformed one fails at construction, and the
// error never echoes the secret.
func TestMeshKeyValidation(t *testing.T) {
	const valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	srv, err := New(Config{
		ListenAddr: "127.0.0.1:0",
		StateDir:   t.TempDir(),
		MeshKey:    valid,
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatalf("New with mesh key: %v", err)
	}
	if !srv.MeshKeyEnabled() {
		t.Error("MeshKeyEnabled = false after configuring a mesh key")
	}

	plain, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), Logger: testLogger()})
	if err != nil {
		t.Fatalf("New without mesh key: %v", err)
	}
	if plain.MeshKeyEnabled() {
		t.Error("MeshKeyEnabled = true without a mesh key")
	}

	bad := valid[:63] + "z"
	_, err = New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), MeshKey: bad, Logger: testLogger()})
	if err == nil {
		t.Fatal("New accepted a malformed mesh key")
	}
	if strings.Contains(err.Error(), bad) {
		t.Errorf("error leaks the mesh key: %v", err)
	}
}

// TestBandwidthConfigValidation covers the derived burst and the rejection of
// nonsensical values.
func TestBandwidthConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Config
		burst int
	}{
		{"no limit", Config{}, 0},
		{"derived from limit", Config{BandwidthLimit: 1 << 20}, 1 << 20},
		{"derived, clamped low", Config{BandwidthLimit: 1024}, MinBandwidthBurst},
		{"derived, clamped high", Config{BandwidthLimit: 1 << 30}, MaxBandwidthBurst},
		{"explicit burst", Config{BandwidthLimit: 1 << 20, BandwidthBurst: 1234}, 1234},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.bandwidthBurst(); got != tc.burst {
				t.Errorf("bandwidthBurst = %d, want %d", got, tc.burst)
			}
		})
	}

	if _, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), BandwidthLimit: -1, Logger: testLogger()}); err == nil {
		t.Error("New accepted a negative bandwidth limit")
	}
	if _, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: t.TempDir(), BandwidthBurst: 1024, Logger: testLogger()}); err == nil {
		t.Error("New accepted a burst without a limit")
	}
}

// TestRelayWithBandwidthLimit checks that the listener wrapper does not break
// the DERP HTTP upgrade or relaying.
func TestRelayWithBandwidthLimit(t *testing.T) {
	_, url := serveTestVeil(t, Config{
		BandwidthLimit: 1 << 20,
		BandwidthBurst: 1 << 16,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alice := dialVeil(t, ctx, url)
	bob := dialVeil(t, ctx, url)

	want := []byte("throttled hello")
	if err := alice.Send(bob.SelfPublicKey(), want); err != nil {
		t.Fatalf("send: %v", err)
	}

	for {
		msg, err := bob.Recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if _, ok := msg.(derp.ServerInfoMessage); ok {
			continue
		}
		pkt, ok := msg.(derp.ReceivedPacket)
		if !ok {
			t.Fatalf("received message type %T, want derp.ReceivedPacket", msg)
		}
		if string(pkt.Data) != string(want) {
			t.Errorf("packet data = %q, want %q", pkt.Data, want)
		}
		return
	}
}
