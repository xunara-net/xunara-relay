package relay

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

func TestSTUNBindFailureDoesNotPublishTCPReady(test *testing.T) {
	occupied, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	defer occupied.Close()
	_, port, _ := net.SplitHostPort(occupied.LocalAddr().String())
	number, _ := strconv.Atoi(port)
	server, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: test.TempDir(), STUN: true, STUNPort: number, Logger: testLogger()})
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	if err := server.Serve(test.Context()); err == nil {
		test.Fatal("STUN bind failure was ignored")
	}
	if server.Addr() != nil || server.STUNAddr() != nil {
		test.Fatal("failed startup published ready listeners")
	}
}

func TestSTUNRequestHealthAndShutdown(test *testing.T) {
	available, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(available.LocalAddr().String())
	number, _ := strconv.Atoi(port)
	available.Close()
	server, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: test.TempDir(), STUN: true, STUNPort: number, Logger: testLogger()})
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(test.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	for attempt := 0; attempt < 100 && server.STUNAddr() == nil; attempt++ {
		time.Sleep(10 * time.Millisecond)
	}
	if server.STUNAddr() == nil {
		test.Fatal("STUN did not bind")
	}
	if err := CheckSTUN(test.Context(), server.STUNAddr().String()); err != nil {
		test.Fatal(err)
	}
	if err := server.CheckHealth(test.Context()); err != nil {
		test.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			test.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		test.Fatal("shutdown did not finish")
	}
	probeContext, stop := context.WithTimeout(test.Context(), 200*time.Millisecond)
	defer stop()
	if CheckSTUN(probeContext, server.STUNAddr().String()) == nil {
		test.Fatal("stopped STUN still responds")
	}
}

func TestCheckSTUNRejectsForgedTransaction(test *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var packet [1024]byte
		_, remote, err := listener.ReadFrom(packet[:])
		if err != nil {
			return
		}
		mapped := remote.(*net.UDPAddr).AddrPort()
		listener.WriteTo(stun.Response(stun.NewTxID(), mapped), remote)
	}()
	if CheckSTUN(test.Context(), listener.LocalAddr().String()) == nil {
		test.Fatal("accepted another transaction's STUN response")
	}
	<-done
}

func TestInvalidSTUNPortsRejected(test *testing.T) {
	for _, port := range []int{-1, 65536} {
		if server, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: test.TempDir(), STUN: true, STUNPort: port}); err == nil {
			server.Close()
			test.Fatalf("accepted enabled STUN port %d", port)
		}
	}
}

func TestUnverifiedSTUNIsNotAdvertised(test *testing.T) {
	server, err := New(Config{ListenAddr: "127.0.0.1:9091", HostName: "relay.example.com", StateDir: test.TempDir(), STUN: true, STUNPort: 9091, STUNUnadvertised: true, Logger: testLogger()})
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	derpMap, err := server.DERPMap()
	if err != nil {
		test.Fatal(err)
	}
	if derpMap.Regions[DefaultRegionID].Nodes[0].STUNPort != -1 {
		test.Fatal("unverified public UDP endpoint was published")
	}
	if server.stunPort() != 9091 || !server.cfg.STUN {
		test.Fatal("unadvertised mode disabled the local UDP listener")
	}
}
