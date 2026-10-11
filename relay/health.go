package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"tailscale.com/net/tlsdial"
)

// CheckHealth 检查本机实际监听和探测路径；不等于公网可达、STUN 可用或数据面连通。
func (server *Server) CheckHealth(ctx context.Context) error {
	if server.RuntimeConfiguration().DesiredState != "online" {
		return errors.New("relay: service is not enabled")
	}
	address := server.Addr()
	if address == nil {
		return errors.New("relay: listener is not ready")
	}
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return errors.New("relay: listener address invalid")
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	target := net.JoinHostPort(host, port)
	scheme := "http"
	configuration := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: server.cfg.HostName}
	if server.cfg.TLS() {
		scheme = "https"
		pin := strings.TrimPrefix(server.certPin, "sha256-raw:")
		if pin == "" && server.cfg.CertFile != "" {
			certificate, readErr := os.ReadFile(server.cfg.CertFile)
			if readErr != nil {
				return errors.New("relay: local certificate unavailable")
			}
			block, _ := pem.Decode(certificate)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.New("relay: local certificate invalid")
			}
			digest := sha256.Sum256(block.Bytes)
			pin = hex.EncodeToString(digest[:])
		}
		if pin != "" {
			tlsdial.SetConfigExpectedCertHash(configuration, pin)
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: configuration, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, target)
		}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := &url.URL{Scheme: scheme, Host: net.JoinHostPort(server.cfg.HostName, port), Path: "/derp/probe"}
	if server.cfg.HostName == "" {
		endpoint.Host = target
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.New("relay: local probe configuration invalid")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("relay: local listener or TLS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("relay: local probe returned unexpected status")
	}
	return nil
}
