// Package registration implements the Xunara Relay control protocol: a relay
// exchanges a one-time enrollment token for a long-lived identity, then keeps
// the control plane informed with heartbeats and picks up remote configuration.
//
// The relay data plane never depends on the control plane. An already-enrolled
// relay keeps serving DERP/STUN while the control plane is unreachable; a
// managed relay with no identity refuses to guess one and exits instead
// (fail closed), because a relay that joins the wrong tailnet is worse than a
// relay that is down.
package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Enrollment and heartbeat endpoints on the Xunara control plane.
const (
	EnrollPath    = "/api/relay/v1/enroll"
	HeartbeatPath = "/api/relay/v1/heartbeat"
)

// Visibility values a relay may request at enrollment.
const (
	VisibilityPrivate      = "private"
	VisibilityOrganization = "organization"
	VisibilityPublic       = "public"
)

// EnrollRequest is what a relay tells the control plane about itself.
type EnrollRequest struct {
	// Name is the human-readable relay name shown in the console.
	Name string `json:"name"`
	// RegionCode and RegionName describe the DERP region this relay serves.
	RegionCode string `json:"region_code"`
	RegionName string `json:"region_name"`
	// HostName is the publicly reachable name clients will dial.
	HostName string `json:"hostname"`
	// NodeKey is the relay's DERP node public key ("nodekey:...").
	NodeKey string `json:"node_key"`
	// Version is the relay build version.
	Version string `json:"version"`
	// DERPPort and STUNPort are the ports the relay actually serves.
	DERPPort int `json:"derp_port"`
	STUNPort int `json:"stun_port"`
	// Visibility is one of the Visibility* values; empty means private.
	Visibility string `json:"visibility,omitempty"`
}

// Identity is the long-lived credential the control plane issues in exchange
// for a one-time enrollment token.
type Identity struct {
	RelayID    string `json:"relay_id"`
	Token      string `json:"relay_token"`
	ControlURL string `json:"control_url"`
	Name       string `json:"name,omitempty"`
}

// Valid reports whether the identity can be used to authenticate.
func (i Identity) Valid() bool {
	return i.RelayID != "" && i.Token != "" && i.ControlURL != ""
}

// LoadIdentity reads a stored identity. A missing file is not an error: it
// means the relay has not enrolled yet.
func LoadIdentity(path string) (Identity, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Identity{}, false, nil
	}
	if err != nil {
		return Identity{}, false, fmt.Errorf("reading relay identity: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return Identity{}, false, fmt.Errorf("parsing relay identity %s: %w", path, err)
	}
	return id, id.Valid(), nil
}

// Save writes the identity with 0600 permissions, creating the parent
// directory if needed. The token is a credential: it never goes to stdout,
// logs or command-line arguments.
func (i Identity) Save(path string) error {
	if !i.Valid() {
		return errors.New("refusing to store an incomplete relay identity")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating identity directory: %w", err)
	}
	blob, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("writing relay identity: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("storing relay identity: %w", err)
	}
	return nil
}

// Status is the relay's self-report on each heartbeat.
type Status struct {
	Version          string `json:"version"`
	Healthy          bool   `json:"healthy"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	ConnectedClients int    `json:"connected_clients"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
}

// RemoteConfig is the control plane's answer to a heartbeat: the desired
// state of this relay. Unknown fields are ignored so a newer control plane
// never breaks an older relay.
type RemoteConfig struct {
	// DesiredState is "online", "maintenance", "disabled" or "revoked".
	DesiredState string `json:"desired_state"`
	// ConfigVersion changes whenever any field below changes.
	ConfigVersion string `json:"config_version"`
	// BandwidthLimit is a per-connection byte/second limit; zero leaves the
	// relay's own configuration alone, -1 removes the limit.
	BandwidthLimit int64 `json:"bandwidth_limit"`
	// RegionName renames the region without a restart; empty keeps it.
	RegionName string `json:"region_name"`
}

// Error is a non-2xx answer from the control plane.
type Error struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("control plane answered %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("control plane answered %d: %s", e.StatusCode, e.Message)
}

// Client talks to the Xunara control plane.
type Client struct {
	// ControlURL is the base URL, e.g. "https://control.example.com".
	ControlURL string
	// Token is the enrollment token (one call) or the relay token.
	Token string
	// HTTPClient is optional; a client with a timeout is used by default.
	HTTPClient *http.Client
	// UserAgent identifies the relay build.
	UserAgent string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// do posts a JSON body and decodes the JSON answer into out.
func (c *Client) do(ctx context.Context, path string, token string, body, out any) error {
	if c.ControlURL == "" {
		return errors.New("relay registration: ControlURL is required")
	}
	blob, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ControlURL+path, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Bound the answer: a relay never needs more than a few KiB of config.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var apiErr struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(raw, &apiErr)
		msg := apiErr.Message
		if msg == "" {
			msg = apiErr.Error
		}
		if msg == "" {
			msg = string(raw)
		}
		return &Error{StatusCode: resp.StatusCode, Code: apiErr.Code, Message: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding control plane answer: %w", err)
	}
	return nil
}

// Enroll exchanges the one-time enrollment token for a long-lived identity.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (Identity, error) {
	var out Identity
	if err := c.do(ctx, EnrollPath, c.Token, req, &out); err != nil {
		return Identity{}, err
	}
	if !out.Valid() {
		return Identity{}, errors.New("control plane answered enrollment without an identity")
	}
	return out, nil
}

// Heartbeat reports the relay's status and returns the desired configuration.
func (c *Client) Heartbeat(ctx context.Context, status Status) (RemoteConfig, error) {
	var out RemoteConfig
	if err := c.do(ctx, HeartbeatPath, c.Token, status, &out); err != nil {
		return RemoteConfig{}, err
	}
	return out, nil
}

// RunHeartbeats sends a heartbeat every interval until ctx is done, calling
// apply for each accepted configuration. Transient failures are reported to
// onError and retried on the next tick: a relay must survive a control plane
// outage without dropping its clients.
func (c *Client) RunHeartbeats(
	ctx context.Context,
	interval time.Duration,
	status func() Status,
	apply func(RemoteConfig),
	onError func(error),
) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastConfig := ""
	for {
		cfg, err := c.Heartbeat(ctx, status())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if onError != nil {
				onError(err)
			}
		} else if apply != nil && cfg.ConfigVersion != lastConfig {
			apply(cfg)
			lastConfig = cfg.ConfigVersion
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
