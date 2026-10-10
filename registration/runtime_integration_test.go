package registration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xunara-net/xunara-relay/registration"
	"github.com/xunara-net/xunara-relay/relay"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func waitRuntime(test *testing.T, condition func() bool) {
	test.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			test.Fatal("managed runtime integration condition timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 真实心跳、Manager、缓存与官方 TLS pin 客户端共跑；不以 UI 夹具替代数据面。
func TestManagedRuntimeHeartbeatWithPinnedTraffic(test *testing.T) {
	var desired atomic.Pointer[registration.RemoteConfig]
	var reported atomic.Pointer[registration.Status]
	var unavailable, revoked atomic.Bool
	desired.Store(&registration.RemoteConfig{DesiredState: "online", ConfigVersion: "1", ConfigRevision: 1})
	controller := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/admit" {
			if unavailable.Load() {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(writer).Encode(tailcfg.DERPAdmitClientResponse{Allow: true})
			return
		}
		if request.URL.Path != registration.HeartbeatPath || request.Header.Get("Authorization") != "Bearer integration-service-secret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if revoked.Load() {
			writer.WriteHeader(http.StatusForbidden)
			json.NewEncoder(writer).Encode(map[string]string{"code": "RELAY_REVOKED", "message": "service revoked"})
			return
		}
		if unavailable.Load() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var status registration.Status
		if json.NewDecoder(request.Body).Decode(&status) != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		reported.Store(&status)
		json.NewEncoder(writer).Encode(desired.Load())
	}))
	defer controller.Close()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	listen := socket.Addr().String()
	socket.Close()
	server, err := relay.New(relay.Config{ListenAddr: listen, HostName: "127.0.0.1", StateDir: test.TempDir(), CertMode: relay.CertModeSelfSigned, VerifyURL: controller.URL + "/admit"})
	if err != nil {
		test.Fatal(err)
	}
	server.AwaitControlAuthorization()
	ctx, cancel := context.WithCancel(test.Context())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx) }()
	test.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				test.Error(err)
			}
		case <-time.After(12 * time.Second):
			test.Error("managed DERP server did not shut down")
		}
	})
	waitRuntime(test, func() bool { return server.Addr() != nil })
	identity := registration.Identity{RelayID: "relay-runtime", Token: "integration-service-secret", ControlURL: controller.URL}
	path := filepath.Join(test.TempDir(), "runtime.json")
	apply := func(configuration registration.RemoteConfig) error {
		return server.ApplyRuntimeConfiguration(relay.RuntimeConfig{DesiredState: configuration.DesiredState, BandwidthLimit: configuration.BandwidthLimit, RegionName: configuration.RegionName})
	}
	current := func() registration.RuntimeState {
		configuration := server.RuntimeConfiguration()
		return registration.RuntimeState{State: configuration.DesiredState, BandwidthLimit: configuration.BandwidthLimit}
	}
	manager, err := registration.NewManager(path, identity, server.PublicKey().String(), apply, current)
	if err != nil {
		test.Fatal(err)
	}
	loopDone := make(chan struct{})
	client := &registration.Client{ControlURL: controller.URL, Token: identity.Token}
	go func() {
		client.RunHeartbeats(ctx, 10*time.Millisecond, func() registration.Status {
			statistics, err := server.Statistics()
			return registration.Status{Healthy: err == nil && current().State == "online", ConnectedClients: statistics.ConnectedClients, BytesIn: statistics.BytesIn, BytesOut: statistics.BytesOut, Execution: manager.Receipt()}
		}, manager.Apply, func(err error) {
			if registration.TerminalIdentityError(err) {
				if err := manager.Revoke(); err != nil {
					test.Error(err)
				}
			}
		})
		close(loopDone)
	}()
	test.Cleanup(func() {
		cancel()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
			test.Error("managed heartbeat worker did not stop")
		}
	})
	waitReport := func(version string) {
		waitRuntime(test, func() bool {
			status := reported.Load()
			return status != nil && status.Execution != nil && status.Execution.Status == "applied" && status.Execution.AppliedVersion == version
		})
	}
	waitReport("1")
	derpMap, _ := server.DERPMap()
	region := derpMap.Regions[relay.DefaultRegionID]
	connect := func() *derphttp.Client {
		test.Helper()
		connection := derphttp.NewRegionClient(key.NewNode(), test.Logf, netmon.NewStatic(), func() *tailcfg.DERPRegion { return region })
		test.Cleanup(func() { connection.Close() })
		connectionCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		if err := connection.Connect(connectionCtx); err != nil {
			test.Fatal(err)
		}
		ready := make(chan error, 1)
		go func() {
			message, err := connection.Recv()
			if _, valid := message.(derp.ServerInfoMessage); !valid && err == nil {
				err = errors.New("official DERP client did not receive ServerInfo")
			}
			ready <- err
		}()
		select {
		case err := <-ready:
			if err != nil {
				test.Fatal(err)
			}
		case <-connectionCtx.Done():
			test.Fatal(connectionCtx.Err())
		}
		return connection
	}
	sender, receiver := connect(), connect()
	transfer := func(payload string) {
		test.Helper()
		if err := sender.Send(receiver.SelfPublicKey(), []byte(payload)); err != nil {
			test.Fatal(err)
		}
		received := make(chan error, 1)
		go func() {
			for {
				message, err := receiver.Recv()
				if err != nil {
					received <- err
					return
				}
				if packet, valid := message.(derp.ReceivedPacket); valid {
					if string(packet.Data) != payload {
						received <- errors.New("incorrect DERP payload")
					} else {
						received <- nil
					}
					return
				}
			}
		}()
		select {
		case err := <-received:
			if err != nil {
				test.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			test.Fatal("managed pinned transfer timed out")
		}
	}
	transfer("real managed traffic")
	waitRuntime(test, func() bool {
		status := reported.Load()
		return status.ConnectedClients == 2 && status.BytesIn > 0 && status.BytesOut > 0
	})
	desired.Store(&registration.RemoteConfig{DesiredState: "maintenance", ConfigVersion: "2", ConfigRevision: 2, BandwidthLimit: -1})
	waitReport("2")
	unavailable.Store(true)
	transfer("existing traffic survives maintenance and controller outage")
	if current().State != "maintenance" {
		test.Fatal("controller outage silently changed runtime configuration")
	}
	unavailable.Store(false)
	desired.Store(&registration.RemoteConfig{DesiredState: "disabled", ConfigVersion: "3", ConfigRevision: 3})
	waitReport("3")
	waitRuntime(test, func() bool {
		status := reported.Load()
		return !status.Healthy && status.ConnectedClients == 0 && status.Execution.State == "disabled"
	})
	sender.Close()
	receiver.Close()
	desired.Store(&registration.RemoteConfig{DesiredState: "online", ConfigVersion: "4", ConfigRevision: 4})
	waitReport("4")
	sender, receiver = connect(), connect()
	transfer("resumed managed traffic")
	revoked.Store(true)
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		test.Fatal("revoked service identity kept heartbeating")
	}
	if current().State != "revoked" {
		test.Fatal("revocation did not close managed runtime")
	}
	if _, err := registration.NewManager(path, identity, server.PublicKey().String(), apply, current); !errors.Is(err, registration.ErrServiceRevoked) {
		test.Fatal("restart forgot service revocation")
	}
}
