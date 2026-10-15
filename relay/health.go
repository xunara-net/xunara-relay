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

	"tailscale.com/net/stun"
	"tailscale.com/net/tlsdial"
)

// CheckHealth 检查本机 TLS 和已开启的 STUN 实际请求，不代表公网映射或端到端流量可用。
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
	if server.cfg.STUN {
		address := server.STUNAddr()
		if address == nil {
			return errors.New("relay: STUN listener is not ready")
		}
		host, port, err := net.SplitHostPort(address.String())
		if err != nil {
			return errors.New("relay: STUN listener address invalid")
		}
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		if err := CheckSTUN(ctx, net.JoinHostPort(host, port)); err != nil {
			return err
		}
	}
	return nil
}

// STUNAddr 返回真实 UDP 监听地址；未开启或尚未成功绑定时为 nil。
func (server *Server) STUNAddr() net.Addr {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.stunAddr
}

// CheckSTUN 使用上游 Binding Request/Response 检查 UDP 通路与事务 ID，而不是仅检查端口。
func CheckSTUN(ctx context.Context, address string) error {
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", address)
	if err != nil {
		return errors.New("relay: STUN endpoint unreachable")
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("relay: STUN deadline failed")
	}
	transaction := stun.NewTxID()
	if _, err := connection.Write(stun.Request(transaction)); err != nil {
		return errors.New("relay: STUN request failed")
	}
	var packet [2048]byte
	length, err := connection.Read(packet[:])
	if err != nil {
		return errors.New("relay: STUN response unavailable")
	}
	received, mapped, err := stun.ParseResponse(packet[:length])
	if err != nil || received != transaction || !mapped.IsValid() || mapped.Port() == 0 {
		return errors.New("relay: STUN response invalid")
	}
	return nil
}
