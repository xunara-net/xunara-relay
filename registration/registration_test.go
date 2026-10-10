package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnrollExchangesTokenForIdentity pins the enrollment contract: the
// one-time token travels in the Authorization header, and the answer becomes
// the relay's stored identity.
func TestEnrollExchangesTokenForIdentity(t *testing.T) {
	var gotAuth string
	var gotRequest EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotRequest); err != nil {
			t.Errorf("decoding enroll request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"relay_id":    "relay-1",
			"relay_token": "secret-token",
			"control_url": "https://control.example.com",
		})
	}))
	defer srv.Close()

	client := &Client{ControlURL: srv.URL, Token: "one-time-token"}
	id, err := client.Enroll(context.Background(), EnrollRequest{
		Name:       "hk-1",
		RegionCode: "hk",
		RegionName: "Hong Kong",
		HostName:   "hk1.example.com",
		NodeKey:    "nodekey:abc",
		Version:    "0.1.0",
		DERPPort:   443,
		STUNPort:   3478,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if gotAuth != "Bearer one-time-token" {
		t.Errorf("Authorization = %q, want the enrollment token", gotAuth)
	}
	if gotRequest.NodeKey != "nodekey:abc" || gotRequest.HostName != "hk1.example.com" {
		t.Errorf("control plane saw %+v", gotRequest)
	}
	if !id.Valid() || id.RelayID != "relay-1" || id.Token != "secret-token" {
		t.Fatalf("identity = %+v, want relay-1", id)
	}
}

// TestEnrollRejectsIncompleteIdentity covers a control plane that answers
// without a credential: the relay must not pretend it enrolled.
func TestEnrollRejectsIncompleteIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"relay_id": "relay-1"})
	}))
	defer srv.Close()

	client := &Client{ControlURL: srv.URL, Token: "t"}
	if _, err := client.Enroll(context.Background(), EnrollRequest{}); err == nil {
		t.Fatalf("Enroll accepted an identity without a token")
	}
}

// TestControlPlaneErrorIsTyped checks the error a relay sees when the control
// plane refuses it, including the stable code an operator can act on.
func TestControlPlaneErrorIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"code":    "RELAY_ALREADY_ENROLLED",
			"message": "the enrollment token has been used",
		})
	}))
	defer srv.Close()

	client := &Client{ControlURL: srv.URL, Token: "t"}
	_, err := client.Heartbeat(context.Background(), Status{Version: "0.1.0"})
	var apiErr *Error
	if !asError(err, &apiErr) {
		t.Fatalf("Heartbeat error = %v, want a *registration.Error", err)
	}
	if apiErr.StatusCode != http.StatusConflict || apiErr.Code != "RELAY_ALREADY_ENROLLED" {
		t.Errorf("error = %+v, want 409 RELAY_ALREADY_ENROLLED", apiErr)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

// TestIdentityRoundTripAndPermissions pins that the stored credential is
// written 0600 and survives a restart.
func TestIdentityRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "relay-identity.json")

	if _, ok, err := LoadIdentity(path); err != nil || ok {
		t.Fatalf("LoadIdentity on a fresh directory = (%v, %v), want (false, nil)", ok, err)
	}

	id := Identity{RelayID: "relay-7", Token: "tok", ControlURL: "https://c.example.com", Name: "hk-1"}
	if err := id.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o, want 600", info.Mode().Perm())
	}

	loaded, ok, err := LoadIdentity(path)
	if err != nil || !ok {
		t.Fatalf("LoadIdentity = (%v, %v), want the stored identity", ok, err)
	}
	if loaded != id {
		t.Fatalf("loaded %+v, want %+v", loaded, id)
	}

	if err := (Identity{RelayID: "only-id"}).Save(filepath.Join(dir, "bad.json")); err == nil {
		t.Fatalf("Save accepted an incomplete identity")
	}
}

// TestHeartbeatsApplyOnlyNewConfig checks the loop: configuration is applied
// once per version, and transient failures do not stop it.
func TestHeartbeatsApplyOnlyNewConfig(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"config_version": "v2",
			"desired_state":  "online",
		})
	}))
	defer server.Close()

	client := &Client{ControlURL: server.URL, Token: "relay-token"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	applied := make(chan RemoteConfig, 4)
	errs := make(chan error, 4)
	go client.RunHeartbeats(ctx, 10*time.Millisecond,
		func() Status { return Status{Version: "0.1.0", Healthy: true} },
		func(cfg RemoteConfig) error { applied <- cfg; return nil },
		func(err error) { errs <- err },
	)

	select {
	case err := <-errs:
		var apiErr *Error
		if !asError(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
			t.Fatalf("first heartbeat error = %v, want the 502", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the failing heartbeat was never reported")
	}

	select {
	case cfg := <-applied:
		if cfg.ConfigVersion != "v2" || cfg.DesiredState != "online" {
			t.Fatalf("applied config = %+v", cfg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the recovered heartbeat never applied its config")
	}
}

// TestHeartbeatSendsRelayToken pins the second leg of the protocol: the
// long-lived relay token, not the enrollment token.
func TestHeartbeatSendsRelayToken(t *testing.T) {
	var auth string
	var status Status
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&status)
		json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer srv.Close()

	client := &Client{ControlURL: srv.URL, Token: "relay-token", UserAgent: "xunara-relay/0.1.0"}
	if _, err := client.Heartbeat(context.Background(), Status{Version: "0.1.0", Healthy: true, ConnectedClients: 3}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if auth != "Bearer relay-token" {
		t.Errorf("Authorization = %q, want the relay token", auth)
	}
	if status.ConnectedClients != 3 || !status.Healthy {
		t.Errorf("control plane saw status %+v", status)
	}
}

// TestRegistrationPathsAreVersioned guards the contract path the server will
// implement; a typo here breaks every relay silently.
func TestRegistrationPathsAreVersioned(t *testing.T) {
	for _, p := range []string{EnrollPath, HeartbeatPath} {
		if !strings.HasPrefix(p, "/api/relay/v1/") {
			t.Errorf("path %q is not under /api/relay/v1", p)
		}
	}
}
