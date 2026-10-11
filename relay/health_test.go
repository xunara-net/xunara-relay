package relay

import (
	"context"
	"testing"
	"time"
)

func TestLocalHealthUsesLivePinnedListener(test *testing.T) {
	server, err := New(selfSignedConfig(test, "127.0.0.1", test.TempDir()))
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	if server.CheckHealth(test.Context()) == nil {
		test.Fatal("not-yet-listening server reported healthy")
	}
	ctx, cancel := context.WithCancel(test.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for attempt := 0; attempt < 100; attempt++ {
		if server.CheckHealth(test.Context()) == nil {
			break
		}
		if attempt == 99 {
			test.Fatal("verified local TLS probe did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "maintenance"}); err != nil {
		test.Fatal(err)
	}
	if server.CheckHealth(test.Context()) == nil {
		test.Fatal("maintenance reported healthy")
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "online"}); err != nil {
		test.Fatal(err)
	}
	if server.CheckHealth(test.Context()) != nil {
		test.Fatal("online listener did not recover")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		test.Fatal("relay did not stop")
	}
	if server.CheckHealth(test.Context()) == nil {
		test.Fatal("stale listener address reported healthy after stop")
	}
}

func TestLocalHealthChecksCancellationAndCertificatePin(test *testing.T) {
	server, err := New(selfSignedConfig(test, "127.0.0.1", test.TempDir()))
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(test.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for attempt := 0; server.Addr() == nil && attempt < 100; attempt++ {
		time.Sleep(10 * time.Millisecond)
	}
	canceled, stop := context.WithCancel(test.Context())
	stop()
	if server.CheckHealth(canceled) == nil {
		test.Fatal("canceled health check succeeded")
	}
	original := server.certPin
	server.certPin = "sha256-raw:0000000000000000000000000000000000000000000000000000000000000000"
	if server.CheckHealth(test.Context()) == nil {
		test.Fatal("wrong local certificate pin accepted")
	}
	server.certPin = original
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		test.Fatal("relay did not stop")
	}
}
