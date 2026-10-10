// Package registration implements the Xunara Relay control protocol: a relay
// exchanges a one-time enrollment token for a long-lived identity, then keeps
// the control plane informed with heartbeats and picks up remote configuration.
//
// 运行中控制面故障不影响既有连接；新进程必须确认授权，不能凭缓存开放数据面。
package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	RegionID   int    `json:"region_id,omitempty"`
	CertName   string `json:"cert_name,omitempty"`
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
	if !id.Valid() {
		return Identity{}, false, errors.New("stored relay identity is incomplete; refusing to start as an unmanaged relay")
	}
	if _, err := ControlBaseURL(id.ControlURL); err != nil {
		return Identity{}, false, err
	}
	return id, true, nil
}

// 控制面地址只能是无凭据的根地址，防止 URL 错配将服务密钥写入日志或重定向目标。
func ControlBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || strings.Trim(parsed.Path, "/") != "" {
		return "", errors.New("relay control URL must be an HTTP(S) root address without credentials, query or fragment")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
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
	Version          string     `json:"version"`
	Healthy          bool       `json:"healthy"`
	UptimeSeconds    int64      `json:"uptime_seconds"`
	ConnectedClients int        `json:"connected_clients"`
	BytesIn          int64      `json:"bytes_in"`
	BytesOut         int64      `json:"bytes_out"`
	Execution        *Execution `json:"execution,omitempty"`
}

// RemoteConfig is the control plane's answer to a heartbeat: the desired
// state of this relay. Unknown fields are ignored so a newer control plane
// never breaks an older relay.
type RemoteConfig struct {
	// DesiredState is "online", "maintenance", "disabled" or "revoked".
	DesiredState string `json:"desired_state"`
	// ConfigVersion changes whenever any field below changes.
	ConfigVersion  string `json:"config_version"`
	ConfigRevision uint64 `json:"config_revision,omitempty"`
	// BandwidthLimit is a per-connection byte/second limit; zero leaves the
	// relay's own configuration alone, -1 removes the limit.
	BandwidthLimit int64 `json:"bandwidth_limit"`
	// RegionName renames the region without a restart; empty restores the local name.
	RegionName string `json:"region_name"`
}

// Error is a non-2xx answer from the control plane.
type Error struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	// 外部错误体可能回显 Authorization；自动日志只包含状态码。
	return fmt.Sprintf("control plane answered HTTP %d", e.StatusCode)
}

func TerminalIdentityError(err error) bool {
	var response *Error
	return errors.As(err, &response) && (response.StatusCode == http.StatusUnauthorized && response.Code == "RELAY_TOKEN_INVALID" || response.StatusCode == http.StatusForbidden && response.Code == "RELAY_REVOKED")
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
	base, err := ControlBaseURL(c.ControlURL)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	client := *c.httpClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
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
	apply func(RemoteConfig) error,
	onError func(error),
) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastConfig *RemoteConfig
	for {
		cfg, err := c.Heartbeat(ctx, status())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if onError != nil {
				onError(err)
			}
			if TerminalIdentityError(err) {
				return
			}
		} else if apply != nil && (lastConfig == nil || cfg != *lastConfig) {
			if err := apply(cfg); err != nil {
				if onError != nil {
					onError(err)
				}
			} else {
				lastConfig = &cfg
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
