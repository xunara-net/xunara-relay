package registration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func runtimeManagerFixture(test *testing.T, path string, identity Identity) (*Manager, *RuntimeState) {
	test.Helper()
	actual := &RuntimeState{State: "pending", BandwidthLimit: 2048}
	manager, err := NewManager(path, identity, "nodekey:test", func(configuration RemoteConfig) error {
		actual.State = configuration.DesiredState
		if configuration.BandwidthLimit == -1 {
			actual.BandwidthLimit = 0
		} else if configuration.BandwidthLimit == 0 {
			actual.BandwidthLimit = 2048
		} else {
			actual.BandwidthLimit = configuration.BandwidthLimit
		}
		return nil
	}, func() RuntimeState { return *actual })
	if err != nil {
		test.Fatal(err)
	}
	return manager, actual
}

func TestRuntimeManagerPersistenceRetryAndRestart(test *testing.T) {
	path := filepath.Join(test.TempDir(), "runtime.json")
	identity := Identity{"relay-test", "private-service-secret", "https://tenant.example.test", ""}
	manager, actual := runtimeManagerFixture(test, path, identity)
	configuration := RemoteConfig{DesiredState: "online", ConfigVersion: "7", BandwidthLimit: 8192}
	writer := manager.writeCache
	manager.writeCache = func(string, []byte, os.FileMode) error { return errors.New(identity.Token) }
	if err := manager.Apply(configuration); err == nil || strings.Contains(err.Error(), identity.Token) || manager.Receipt().Status != "failed" || actual.State != "pending" {
		test.Fatal("cache failure was treated as execution or exposed a secret")
	}
	manager.writeCache = writer
	apply := manager.apply
	manager.apply = func(RemoteConfig) error { return errors.New(identity.Token) }
	if err := manager.Apply(configuration); err == nil || manager.Receipt().ErrorCode != "apply_failed" || actual.State != "pending" {
		test.Fatal("apply failure was recorded as success")
	}
	manager.apply = apply
	if err := manager.Apply(configuration); err != nil || manager.Receipt().AppliedVersion != "7" || actual.BandwidthLimit != 8192 {
		test.Fatalf("retry did not execute: %v", err)
	}
	manager.apply = func(RemoteConfig) error { test.Fatal("duplicate configuration was applied again"); return nil }
	if err := manager.Apply(configuration); err != nil {
		test.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		test.Fatal("runtime cache is not private")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), identity.Token) {
		test.Fatal("runtime cache contains a raw service secret")
	}
	restarted, restartedActual := runtimeManagerFixture(test, path, identity)
	if restarted.Receipt() != nil || restartedActual.State != "pending" {
		test.Fatal("restart treated cached configuration as fresh authorization")
	}
	if err := restarted.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "6"}); err == nil || restartedActual.State != "pending" {
		test.Fatal("restart accepted an older configuration")
	}
	conflicting := configuration
	conflicting.DesiredState = "disabled"
	if err := restarted.Apply(conflicting); err == nil || restartedActual.State != "pending" {
		test.Fatal("same version accepted a different body")
	}
	if err := restarted.Apply(configuration); err != nil || restartedActual.State != "online" {
		test.Fatal("fresh authorization did not reapply cached configuration")
	}
}

func TestRuntimeManagerStopsDespiteCacheFailureAndRetainsHighWater(test *testing.T) {
	manager, actual := runtimeManagerFixture(test, filepath.Join(test.TempDir(), "runtime.json"), Identity{"relay-test", "private", "https://tenant.example.test", ""})
	if err := manager.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "1"}); err != nil {
		test.Fatal(err)
	}
	manager.writeCache = func(string, []byte, os.FileMode) error { return errors.New("disk unavailable") }
	if err := manager.Apply(RemoteConfig{DesiredState: "disabled", ConfigVersion: "2"}); err == nil || actual.State != "disabled" || manager.Receipt().ErrorCode != "cache_write_failed" || manager.Receipt().AppliedVersion != "1" {
		test.Fatal("disk failure left the relay enabled or invented a successful version")
	}
	if err := manager.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "1"}); err == nil || actual.State != "disabled" {
		test.Fatal("older configuration reopened data plane after a cache failure")
	}
	if err := manager.Revoke(); err == nil || actual.State != "revoked" {
		test.Fatal("revocation did not stop data plane before cache failure")
	}
	if err := manager.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "3"}); !errors.Is(err, ErrServiceRevoked) {
		test.Fatal("revoked service identity was reused")
	}
}

func TestRuntimeManagerRejectsCorruptionAndIdentityConfusion(test *testing.T) {
	path := filepath.Join(test.TempDir(), "runtime.json")
	identity := Identity{"relay-test", "private", "https://tenant.example.test", ""}
	manager, _ := runtimeManagerFixture(test, path, identity)
	if err := manager.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "1"}); err != nil {
		test.Fatal(err)
	}
	current := func() RuntimeState { return RuntimeState{State: "pending"} }
	apply := func(RemoteConfig) error { return nil }
	for _, other := range []Identity{{"another", identity.Token, identity.ControlURL, ""}, {identity.RelayID, "another", identity.ControlURL, ""}, {identity.RelayID, identity.Token, "https://another.example.test", ""}} {
		if _, err := NewManager(path, other, "nodekey:test", apply, current); err == nil {
			test.Fatal("cache identity mismatch was ignored")
		}
	}
	if _, err := NewManager(path, identity, "nodekey:another", apply, current); err == nil {
		test.Fatal("cache was reused for a different DERP key")
	}
	if err := manager.Revoke(); err != nil {
		test.Fatal(err)
	}
	if _, err := NewManager(path, identity, "nodekey:test", apply, current); !errors.Is(err, ErrServiceRevoked) {
		test.Fatal("revocation tombstone was ignored on restart")
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := NewManager(path, identity, "nodekey:test", apply, current); err == nil {
		test.Fatal("corrupt cache was treated as a new relay")
	}
}

func TestRuntimeConfigurationSequenceCompatibility(test *testing.T) {
	for _, invalid := range []RemoteConfig{
		{DesiredState: "online", ConfigVersion: "v1"}, {DesiredState: "online", ConfigVersion: "01"},
		{DesiredState: "online", ConfigVersion: "0"}, {DesiredState: "online", ConfigVersion: "1", ConfigRevision: 1 << 53},
		{DesiredState: "future", ConfigVersion: "1"}, {DesiredState: "online", ConfigVersion: "1", BandwidthLimit: -2},
	} {
		if _, _, err := validateConfiguration(invalid); err == nil {
			test.Fatalf("accepted invalid configuration: %+v", invalid)
		}
	}
	for _, configuration := range []RemoteConfig{{DesiredState: "online", ConfigVersion: "7"}, {DesiredState: "online", ConfigVersion: "opaque-token", ConfigRevision: 7}} {
		if _, revision, err := validateConfiguration(configuration); err != nil || revision != 7 {
			test.Fatalf("compatible sequence rejected: %v", err)
		}
	}
}

func TestHeartbeatsRetryFailedExecutionAndTerminateRevocation(test *testing.T) {
	var calls, applies atomic.Int32
	ctx, cancel := context.WithCancel(test.Context())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		json.NewEncoder(writer).Encode(RemoteConfig{DesiredState: "online", ConfigVersion: "opaque"})
	}))
	defer server.Close()
	finished := make(chan struct{})
	client := &Client{ControlURL: server.URL, Token: "private"}
	go func() {
		client.RunHeartbeats(ctx, 5*time.Millisecond, func() Status { return Status{} }, func(RemoteConfig) error {
			if applies.Add(1) == 1 {
				return errors.New("temporary execution failure")
			}
			cancel()
			return nil
		}, nil)
		close(finished)
	}()
	select {
	case <-finished:
		if applies.Load() != 2 || calls.Load() != 2 {
			test.Fatal("failed execution was not retried")
		}
	case <-time.After(time.Second):
		test.Fatal("heartbeat retry timed out")
	}
	for _, terminal := range []Error{{401, "RELAY_TOKEN_INVALID", "private-secret"}, {403, "RELAY_REVOKED", "private-secret"}} {
		var terminalCalls atomic.Int32
		endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			terminalCalls.Add(1)
			writer.WriteHeader(terminal.StatusCode)
			json.NewEncoder(writer).Encode(map[string]string{"code": terminal.Code, "message": terminal.Message})
		}))
		client := &Client{ControlURL: endpoint.URL, Token: "private"}
		var stopped bool
		client.RunHeartbeats(test.Context(), time.Millisecond, func() Status { return Status{} }, nil, func(err error) {
			stopped = TerminalIdentityError(err)
			if strings.Contains(err.Error(), terminal.Message) {
				test.Fatal("remote error body leaked into logs")
			}
		})
		endpoint.Close()
		if !stopped || terminalCalls.Load() != 1 {
			test.Fatal("terminal service error continued retrying")
		}
	}
}

func TestRuntimeManagerConcurrentReceipts(test *testing.T) {
	manager, _ := runtimeManagerFixture(test, filepath.Join(test.TempDir(), "runtime.json"), Identity{"relay-test", "private", "https://tenant.example.test", ""})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Go(func() {
			for iteration := 1; iteration < 12; iteration++ {
				manager.Apply(RemoteConfig{DesiredState: "online", ConfigVersion: "1"})
				if receipt := manager.Receipt(); receipt != nil {
					receipt.Status = "tampered"
				}
			}
		})
	}
	workers.Wait()
	if manager.Receipt().Status != "applied" {
		test.Fatal("receipt pointer mutated stored execution state")
	}
}
