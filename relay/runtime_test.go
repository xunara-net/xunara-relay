package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
)

func TestLimitedConnAccountsLargeBuffers(test *testing.T) {
	for _, read := range []bool{false, true} {
		test.Run(map[bool]string{false: "write", true: "read"}[read], func(test *testing.T) {
			peer, socket := net.Pipe()
			defer peer.Close()
			connection := newLimitedConn(socket, rate.NewLimiter(4096, 1024))
			defer connection.Close()
			payload := make([]byte, 4096)
			started := time.Now()
			if read {
				go func() { peer.Write(payload) }()
				if _, err := io.ReadFull(connection, payload); err != nil {
					test.Fatal(err)
				}
			} else {
				go func() { io.Copy(io.Discard, peer) }()
				if count, err := connection.Write(payload); err != nil || count != len(payload) {
					test.Fatalf("write count=%d err=%v", count, err)
				}
			}
			if time.Since(started) < 500*time.Millisecond {
				test.Fatal("large buffer bypassed bandwidth accounting")
			}
		})
	}
}

func TestLimitedConnReconfigurationAndDeadline(test *testing.T) {
	peer, socket := net.Pipe()
	defer peer.Close()
	connection := newLimitedConn(socket, rate.NewLimiter(1, 1))
	defer connection.Close()
	if err := connection.reserve(1); err != nil {
		test.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- connection.reserve(1024) }()
	time.Sleep(20 * time.Millisecond)
	connection.setRate(rate.Inf, 0)
	select {
	case err := <-result:
		if err != nil {
			test.Fatal(err)
		}
	case <-time.After(time.Second):
		test.Fatal("new configuration did not cancel the old token wait")
	}
	connection.setRate(1, 1)
	connection.SetWriteDeadline(time.Now().Add(40 * time.Millisecond))
	if err := connection.reserve(1024); !errors.Is(err, os.ErrDeadlineExceeded) {
		test.Fatalf("token wait escaped write deadline: %v", err)
	}
	connection.SetWriteDeadline(time.Time{})
	go func() { result <- connection.reserve(1024) }()
	time.Sleep(20 * time.Millisecond)
	connection.SetWriteDeadline(time.Now().Add(40 * time.Millisecond))
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			test.Fatalf("changed deadline: %v", err)
		}
	case <-time.After(time.Second):
		test.Fatal("deadline update did not wake token wait")
	}
}

func TestRuntimeBaselineAndTerminalState(test *testing.T) {
	server, err := New(Config{ListenAddr: "127.0.0.1:0", StateDir: test.TempDir(), BandwidthLimit: 2048, BandwidthBurst: 1024, RegionName: "本地地区", Logger: testLogger()})
	if err != nil {
		test.Fatal(err)
	}
	server.AwaitControlAuthorization()
	for _, limit := range []int64{8192, -1, 0} {
		if err := server.ApplyRuntimeConfiguration(RuntimeConfig{"online", limit, ""}); err != nil {
			test.Fatal(err)
		}
		want := limit
		if limit == -1 {
			want = 0
		} else if limit == 0 {
			want = 2048
		}
		if configuration := server.RuntimeConfiguration(); configuration.BandwidthLimit != want || configuration.RegionName != "本地地区" {
			test.Fatalf("local baseline lost: %+v", configuration)
		}
	}
	for _, invalid := range []RuntimeConfig{{"unknown", 0, ""}, {"online", -2, ""}, {"online", 1 << 53, ""}} {
		before := server.RuntimeConfiguration()
		if err := server.ApplyRuntimeConfiguration(invalid); err == nil || server.RuntimeConfiguration() != before {
			test.Fatal("invalid runtime update changed configuration")
		}
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "revoked"}); err != nil {
		test.Fatal(err)
	}
	server.AwaitControlAuthorization()
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "online"}); err == nil || server.RuntimeConfiguration().DesiredState != "revoked" {
		test.Fatal("revoked runtime was reactivated")
	}
}

func TestLimitedReadDeadlineRetainsUnpaidData(test *testing.T) {
	peer, socket := net.Pipe()
	defer peer.Close()
	connection := newLimitedConn(socket, rate.NewLimiter(1, 1))
	defer connection.Close()
	if err := connection.reserve(1); err != nil {
		test.Fatal(err)
	}
	connection.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	go func() { peer.Write([]byte("retained")) }()
	buffer := make([]byte, 16)
	if count, err := connection.Read(buffer); count != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		test.Fatalf("unpaid data escaped the deadline: count=%d err=%v", count, err)
	}
	connection.SetReadDeadline(time.Time{})
	connection.setRate(rate.Inf, 0)
	if count, err := connection.Read(buffer); err != nil || string(buffer[:count]) != "retained" {
		test.Fatalf("deadline reset lost bytes: count=%d err=%v", count, err)
	}
}

func readyPinnedClient(test *testing.T, ctx context.Context, server *Server) *derphttp.Client {
	test.Helper()
	derpMap, err := server.DERPMap()
	if err != nil {
		test.Fatal(err)
	}
	client, err := regionClient(test, ctx, derpMap, DefaultRegionID)
	if err != nil {
		test.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		for {
			message, err := client.Recv()
			if err != nil {
				ready <- err
				return
			}
			if _, ok := message.(derp.ServerInfoMessage); ok {
				ready <- nil
				return
			}
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			test.Fatal(err)
		}
	case <-ctx.Done():
		test.Fatal(ctx.Err())
	}
	return client
}

func relayPacket(test *testing.T, sender, receiver *derphttp.Client, payload []byte) {
	test.Helper()
	if err := sender.Send(receiver.SelfPublicKey(), payload); err != nil {
		test.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		for {
			message, err := receiver.Recv()
			if err != nil {
				result <- err
				return
			}
			if packet, ok := message.(derp.ReceivedPacket); ok {
				if string(packet.Data) != string(payload) {
					result <- errors.New("relayed payload differs")
				} else {
					result <- nil
				}
				return
			}
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			test.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		test.Fatal("official pinned DERP client did not receive a packet")
	}
}

func TestRuntimeWithOfficialPinnedClients(test *testing.T) {
	server, _ := serveTestVeil(test, selfSignedConfig(test, "127.0.0.1", filepath.Join(test.TempDir(), "certs")))
	ctx, cancel := context.WithTimeout(test.Context(), 20*time.Second)
	defer cancel()
	server.AwaitControlAuthorization()
	derpMap, _ := server.DERPMap()
	if _, err := regionClient(test, ctx, derpMap, DefaultRegionID); err == nil {
		test.Fatal("pending managed relay accepted a new DERP client")
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "online"}); err != nil {
		test.Fatal(err)
	}
	sender, receiver := readyPinnedClient(test, ctx, server), readyPinnedClient(test, ctx, server)
	relayPacket(test, sender, receiver, []byte("real pinned traffic"))
	statistics, err := server.Statistics()
	if err != nil || statistics.ConnectedClients != 2 || statistics.BytesIn == 0 || statistics.BytesOut == 0 {
		test.Fatalf("upstream statistics missing: %+v %v", statistics, err)
	}
	beforeMap, _ := server.DERPMap()
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{"online", 16384, "新地区"}); err != nil {
		test.Fatal(err)
	}
	started := time.Now()
	relayPacket(test, sender, receiver, make([]byte, 24<<10))
	if time.Since(started) < time.Second {
		test.Fatal("hot rate update did not throttle existing official connections")
	}
	afterMap, _ := server.DERPMap()
	if beforeMap.Regions[DefaultRegionID].Nodes[0].CertName != afterMap.Regions[DefaultRegionID].Nodes[0].CertName || afterMap.Regions[DefaultRegionID].RegionName != "新地区" {
		test.Fatal("runtime rename changed certificate pin or did not update region name")
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{"maintenance", -1, ""}); err != nil {
		test.Fatal(err)
	}
	if _, err := regionClient(test, ctx, afterMap, DefaultRegionID); err == nil {
		test.Fatal("maintenance admitted a new DERP client")
	}
	relayPacket(test, sender, receiver, []byte("maintenance preserves existing connection"))
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "disabled"}); err != nil {
		test.Fatal(err)
	}
	disconnected := make(chan error, 1)
	go func() {
		for {
			if _, err := receiver.Recv(); err != nil {
				disconnected <- err
				return
			}
		}
	}()
	select {
	case <-disconnected:
	case <-ctx.Done():
		test.Fatal("disabled runtime retained an existing connection")
	}
	if _, err := regionClient(test, ctx, afterMap, DefaultRegionID); err == nil {
		test.Fatal("disabled runtime admitted a new connection")
	}
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "online"}); err != nil {
		test.Fatal(err)
	}
	relayPacket(test, readyPinnedClient(test, ctx, server), readyPinnedClient(test, ctx, server), []byte("resumed without restart"))
	if err := server.ApplyRuntimeConfiguration(RuntimeConfig{DesiredState: "revoked"}); err != nil {
		test.Fatal(err)
	}
	if _, err := regionClient(test, ctx, afterMap, DefaultRegionID); err == nil {
		test.Fatal("revoked runtime admitted a connection")
	}
}

func TestRuntimeConcurrentUpdatesAndConnectionClose(test *testing.T) {
	server, _ := serveTestVeil(test, Config{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Go(func() {
			for iteration := 0; iteration < 30; iteration++ {
				peer, socket := net.Pipe()
				connection := server.runtime.track(socket)
				server.ApplyRuntimeConfiguration(RuntimeConfig{"online", int64(iteration * 1024), ""})
				connection.SetDeadline(time.Now().Add(time.Second))
				connection.Close()
				peer.Close()
			}
		})
	}
	workers.Wait()
	server.runtime.mu.Lock()
	defer server.runtime.mu.Unlock()
	if len(server.runtime.connections) != 0 {
		test.Fatal("closed connections remained in runtime registry")
	}
}
