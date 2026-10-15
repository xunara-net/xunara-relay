// Package veil implements Xunara Veil, the DERP relay of the Xunara control
// plane.
//
// A Veil node speaks the DERP protocol of the official Tailscale clients:
// it serves the same /derp HTTP upgrade handlers as cmd/derper from the
// upstream repository, and can ask the control plane's admission endpoint
// (POST /derp/admit) whether a node key belongs to this tailnet before
// admitting a client.
package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/atomicfile"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stunserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// DefaultRegionID is the DERP region ID used when [Config.RegionID] is zero.
// It is outside the range used by the official Tailscale DERP map.
const DefaultRegionID = 900

// DefaultSTUNPort is the UDP port STUN runs on when [Config.STUNPort] is zero.
const DefaultSTUNPort = 3478

// MinBandwidthBurst and MaxBandwidthBurst bound the default token bucket for
// [Config.BandwidthLimit]: small enough that a burst cannot defeat a low
// limit, large enough that small protocol exchanges are not delayed.
const (
	MinBandwidthBurst = 64 << 10
	MaxBandwidthBurst = 4 << 20
)

// Config configures a [Server].
type Config struct {
	// ListenAddr is the TCP address the DERP/HTTP server binds to, such as
	// ":3340" or "0.0.0.0:443". Required.
	ListenAddr string
	// HostName is the publicly reachable DNS name of this node. It is used
	// as the TLS server name on client connections and, when non-empty, in
	// generated DERP maps. Required to publish a map.
	HostName string
	// StateDir is the directory holding persistent node state. Defaults to
	// the current directory.
	StateDir string
	// KeyFile is the DERP node private key file. Empty uses
	// <StateDir>/derp.key. The file is created with mode 0600 if missing.
	KeyFile string
	// STUN enables the STUN listener, required by clients for endpoint
	// discovery. New deployments should leave it enabled.
	STUN bool
	// STUNUnadvertised keeps the UDP listener and local checks enabled without
	// advertising an endpoint before its public NAT/firewall mapping is verified.
	STUNUnadvertised bool
	// STUNPort is the UDP port STUN listens on. Zero uses DefaultSTUNPort;
	// a negative value omits STUN from generated maps.
	STUNPort int
	// VerifyURL is the control plane admission endpoint (POST /derp/admit).
	// When empty, every client that presents a well-formed node key is
	// admitted; production deployments should set it.
	VerifyURL string
	// MeshKey is the pre-shared key (64 hexadecimal digits) that trusts other
	// Xunara Veil nodes as DERP mesh peers. Empty disables meshing. It is a
	// shared secret: read it from the environment or a file, never from argv
	// or a URL (AGENTS.md section 8), and it is never logged.
	MeshKey string
	// BandwidthLimit bounds each accepted connection's throughput in bytes
	// per second, counting both directions against one bucket, including TLS
	// and DERP mesh traffic. Zero disables the limit. It is a per-connection
	// fairness bound, not a total capacity cap: N connections may use N times
	// the limit.
	BandwidthLimit int64
	// BandwidthBurst is the token bucket size in bytes for BandwidthLimit.
	// Zero derives one second's worth of tokens, clamped to
	// [MinBandwidthBurst, MaxBandwidthBurst].
	BandwidthBurst int
	// CertFile and CertKeyFile enable TLS serving when both are non-empty.
	// Clients reach DERP over HTTPS by default; plain HTTP is only usable in
	// test deployments that opt into insecure dialing.
	CertFile    string
	CertKeyFile string
	// CertMode selects how TLS certificates are obtained. Empty means
	// "manual when CertFile/CertKeyFile are set, otherwise no TLS".
	// CertModeLetsEncrypt obtains and renews certificates from Let's Encrypt
	// with ACME (TLS-ALPN-01), so a deployment never has to manage cert files
	// by hand; it requires HostName and CertDir. CertModeSelfSigned
	// generates a certificate for a deployment that cannot obtain a public
	// one (a relay reached by IP address); generated DERP maps then carry the
	// certificate's SHA-256 pin, which official clients accept in place of CA
	// validation.
	CertMode string
	// CertDir is the certificate state directory: ACME caches the account key
	// and issued certificates there, and CertModeSelfSigned stores its
	// generated key pair there (default: StateDir). Reusing it across
	// restarts keeps certificates — and therefore published pins — stable.
	// Required with CertModeLetsEncrypt.
	CertDir string
	// ACMEEmail is the optional contact address registered with the ACME
	// account (Let's Encrypt uses it for expiry warnings).
	ACMEEmail string
	// InsecureForTests marks this node as InsecureForTests in generated DERP
	// maps, for local plain-HTTP test deployments only. Never enable it in
	// production.
	InsecureForTests bool
	// RegionID, RegionCode and RegionName describe this node's DERP region
	// in generated maps. RegionID zero uses DefaultRegionID; empty names
	// default to "veil"/"Xunara Veil".
	RegionID   int
	RegionCode string
	RegionName string
	// Logger receives server logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// Server is a Xunara Veil DERP server.
type Server struct {
	cfg Config
	log *slog.Logger

	key     key.NodePrivate
	derp    *derpserver.Server
	runtime *runtimeControl
	metrics expvar.Var

	// acme is the automatic certificate manager (CertModeLetsEncrypt) and
	// nil otherwise. It serves certificates for cfg.HostName only.
	acme *autocert.Manager

	// cert is the generated pair of CertModeSelfSigned, and certPin is the
	// "sha256-raw:" value published in generated DERP maps. Both are zero
	// outside that mode.
	cert    *tls.Certificate
	certPin string

	mu       sync.Mutex
	listener net.Listener
	addr     net.Addr
	stunAddr net.Addr
	cancel   context.CancelFunc
}

// New builds a Veil server from cfg. It loads (or creates) the DERP node key
// but does not bind any sockets until [Server.Serve] is called.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("veil: ListenAddr is required")
	}
	certMode, err := cfg.certMode()
	if err != nil {
		return nil, err
	}
	if certMode == CertModeLetsEncrypt {
		if cfg.CertFile != "" || cfg.CertKeyFile != "" {
			return nil, errors.New("veil: CertMode letsencrypt cannot be combined with CertFile/CertKeyFile")
		}
		if cfg.CertDir == "" {
			return nil, errors.New("veil: CertMode letsencrypt requires CertDir (the ACME cache)")
		}
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "."
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RegionID == 0 {
		cfg.RegionID = DefaultRegionID
	}
	if cfg.RegionCode == "" {
		cfg.RegionCode = "veil"
	}
	if cfg.RegionName == "" {
		cfg.RegionName = "Xunara Veil"
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return nil, fmt.Errorf("veil: invalid ListenAddr %q: %w", cfg.ListenAddr, err)
	}
	if cfg.STUN && (cfg.STUNPort < 0 || cfg.STUNPort > 65535) {
		return nil, errors.New("veil: enabled STUN port must be between 0 and 65535")
	}
	if cfg.BandwidthLimit < 0 || cfg.BandwidthLimit > 1<<53-1 {
		return nil, errors.New("veil: BandwidthLimit must be a non-negative safe integer")
	}
	if cfg.BandwidthBurst < 0 {
		return nil, errors.New("veil: BandwidthBurst must not be negative")
	}
	if cfg.BandwidthLimit == 0 && cfg.BandwidthBurst > 0 {
		return nil, errors.New("veil: BandwidthBurst requires BandwidthLimit")
	}
	if certMode == CertModeSelfSigned {
		if cfg.CertFile != "" || cfg.CertKeyFile != "" {
			return nil, errors.New("veil: CertMode selfsigned cannot be combined with CertFile/CertKeyFile")
		}
		if _, err := cfg.selfSignedHost(); err != nil {
			return nil, err
		}
	}

	keyFile := cfg.KeyFile
	if keyFile == "" {
		keyFile = filepath.Join(cfg.StateDir, "derp.key")
	}
	nodeKey, err := loadOrCreateKey(keyFile, cfg.Logger)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:     cfg,
		log:     cfg.Logger,
		key:     nodeKey,
		derp:    derpserver.New(nodeKey, cfg.logf()),
		runtime: newRuntimeControl(cfg),
	}
	s.metrics = s.derp.ExpVar(false)
	if certMode == CertModeLetsEncrypt {
		host, err := cfg.acmeHost()
		if err != nil {
			return nil, err
		}
		manager := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			// Fail closed: certificates are only ever issued for the
			// configured name, never for whatever SNI a client sends.
			HostPolicy: autocert.HostWhitelist(host),
			Cache:      autocert.DirCache(cfg.CertDir),
		}
		if cfg.ACMEEmail != "" {
			manager.Email = cfg.ACMEEmail
		}
		s.acme = manager
		s.log.Info("veil ACME certificates enabled",
			"host", host, "cache", cfg.CertDir, "challenge", "tls-alpn-01")
	}
	if certMode == CertModeSelfSigned {
		host, err := cfg.selfSignedHost()
		if err != nil {
			return nil, err
		}
		cert, pin, err := loadOrCreateSelfSignedCert(cfg.selfSignedCertDir(), host, cfg.Logger)
		if err != nil {
			return nil, err
		}
		s.cert = &cert
		s.certPin = pin
	}
	if cfg.VerifyURL != "" {
		s.derp.SetVerifyClientURL(cfg.VerifyURL)
	}
	if cfg.MeshKey != "" {
		// ParseDERPMesh's error names the expected shape and never echoes the
		// key, so a bad configuration cannot leak the secret into a log.
		if err := s.derp.SetMeshKey(cfg.MeshKey); err != nil {
			return nil, fmt.Errorf("veil: invalid mesh key: %w", err)
		}
		s.log.Info("veil DERP mesh key enabled")
	}

	if cfg.TLS() {
		if s.acme != nil {
			s.log.Info("veil TLS enabled", "cert", "acme", "host", strings.ToLower(cfg.HostName))
		} else if s.cert != nil {
			s.log.Info("veil TLS enabled", "cert", "self-signed", "host", strings.ToLower(cfg.HostName),
				"pin", s.certPin)
		} else {
			s.log.Info("veil TLS enabled", "cert", cfg.CertFile, "host", cfg.HostName)
		}
	} else {
		s.log.Warn("veil serving DERP without TLS; use this only for local testing")
	}
	if cfg.VerifyURL == "" {
		s.log.Warn("veil has no admission controller; any client presenting a node key will be admitted",
			"hint", "set VerifyURL to the control plane's /derp/admit endpoint")
	}

	return s, nil
}

// bandwidthBurst returns the effective token bucket size.
func (c Config) bandwidthBurst() int {
	if c.BandwidthLimit <= 0 {
		return 0
	}
	if c.BandwidthBurst > 0 {
		return c.BandwidthBurst
	}
	burst := c.BandwidthLimit
	if burst < MinBandwidthBurst {
		burst = MinBandwidthBurst
	}
	if burst > MaxBandwidthBurst {
		burst = MaxBandwidthBurst
	}
	return int(burst)
}

// MeshKeyEnabled reports whether mesh peers are trusted by this node. The key
// itself is never exposed.
func (s *Server) MeshKeyEnabled() bool { return s.derp.HasMeshKey() }

// TLS reports whether the server serves TLS.
func (c Config) TLS() bool {
	mode, err := c.certMode()
	return err == nil && mode != ""
}

// Certificate modes: how Veil obtains the certificate it serves clients.
const (
	// CertModeLetsEncrypt obtains and renews certificates from Let's Encrypt
	// over ACME, proving control of HostName with a TLS-ALPN-01 challenge on
	// this same listener. No certificate files are involved.
	CertModeLetsEncrypt = "letsencrypt"
	// CertModeManual serves the operator's CertFile/CertKeyFile unchanged.
	CertModeManual = "manual"
)

// certMode normalizes the configured certificate mode: letsencrypt, manual,
// or "" for a server that does not serve TLS.
func (c Config) certMode() (string, error) {
	switch c.CertMode {
	case "":
		if c.CertFile == "" && c.CertKeyFile == "" {
			return "", nil
		}
		if c.CertFile == "" || c.CertKeyFile == "" {
			return "", errors.New("veil: CertFile and CertKeyFile must be set together")
		}
		return CertModeManual, nil
	case CertModeManual:
		if c.CertFile == "" || c.CertKeyFile == "" {
			return "", errors.New("veil: CertMode manual requires both CertFile and CertKeyFile")
		}
		return CertModeManual, nil
	case CertModeLetsEncrypt:
		return CertModeLetsEncrypt, nil
	case CertModeSelfSigned:
		return CertModeSelfSigned, nil
	default:
		return "", fmt.Errorf("veil: unsupported CertMode %q (want %q, %q or %q)",
			c.CertMode, CertModeLetsEncrypt, CertModeManual, CertModeSelfSigned)
	}
}

// acmeHost validates and normalizes the hostname an automatic certificate is
// issued for. ACME only issues for DNS names, and the name must match the SNI
// clients send, so anything that cannot be an SNI host is refused here.
func (c Config) acmeHost() (string, error) {
	host := strings.ToLower(strings.TrimSpace(c.HostName))
	switch {
	case host == "":
		return "", errors.New("veil: CertMode letsencrypt requires HostName")
	case net.ParseIP(host) != nil:
		return "", errors.New("veil: CertMode letsencrypt requires HostName to be a DNS name, not an IP address")
	case !strings.Contains(host, "."):
		return "", fmt.Errorf("veil: CertMode letsencrypt requires a fully qualified HostName (got %q)", c.HostName)
	case strings.ContainsAny(host, " :/\t\r\n"):
		return "", fmt.Errorf("veil: HostName %q is not a valid DNS name", c.HostName)
	case !strings.ContainsAny(host, "abcdefghijklmnopqrstuvwxyz0123456789-."):
		return "", fmt.Errorf("veil: HostName %q is not a valid DNS name", c.HostName)
	}
	return host, nil
}

// logf adapts the server logger to the derpserver logger interface.
func (c Config) logf() func(string, ...any) {
	return func(format string, args ...any) {
		c.Logger.Debug(fmt.Sprintf(format, args...))
	}
}

// loadOrCreateKey reads the node private key from path, generating and
// persisting a new one when the file does not exist.
func loadOrCreateKey(path string, log *slog.Logger) (key.NodePrivate, error) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		k := key.NewNode()
		blob, err := json.MarshalIndent(configFile{PrivateKey: k}, "", "\t")
		if err != nil {
			return key.NodePrivate{}, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return key.NodePrivate{}, fmt.Errorf("veil: creating state directory: %w", err)
		}
		if err := atomicfile.WriteFile(path, blob, 0o600); err != nil {
			return key.NodePrivate{}, fmt.Errorf("veil: writing node key: %w", err)
		}
		log.Info("veil generated a new DERP node key", "path", path, "public_key", k.Public().ShortString())
		return k, nil
	case err != nil:
		return key.NodePrivate{}, fmt.Errorf("veil: reading node key: %w", err)
	}

	var cfg configFile
	if err := json.Unmarshal(b, &cfg); err != nil {
		return key.NodePrivate{}, fmt.Errorf("veil: parsing node key file %s: %w", path, err)
	}
	if cfg.PrivateKey.IsZero() {
		return key.NodePrivate{}, fmt.Errorf("veil: node key file %s contains no private key", path)
	}

	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		log.Warn("veil node key file is readable beyond its owner", "path", path, "mode", fi.Mode().Perm().String())
	}
	return cfg.PrivateKey, nil
}

// configFile is the on-disk node key format, matching derper's config file.
type configFile struct {
	PrivateKey key.NodePrivate
}

// PublicKey returns the server's DERP node public key, which clients pin
// during the DERP handshake.
func (s *Server) PublicKey() key.NodePublic { return s.key.Public() }

// Addr returns the TCP address the server is bound to, or nil before Serve.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Handler returns the HTTP handler serving the DERP protocol.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	derpHandler := derpserver.AddWebSocketSupport(s.derp, derpserver.Handler(s.derp))
	mux.HandleFunc("/derp", func(writer http.ResponseWriter, request *http.Request) {
		if s.RuntimeConfiguration().DesiredState != "online" {
			writer.Header().Set("Retry-After", "60")
			http.Error(writer, "relay is not accepting new clients", http.StatusServiceUnavailable)
			return
		}
		derpHandler.ServeHTTP(writer, request)
	})
	// Clients without UDP access probe these as a replacement for STUN.
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
	mux.HandleFunc("/", s.handleRoot)

	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"name":       "Xunara Veil",
		"public_key": s.key.Public().UntypedHexString(),
	})
}

// Serve binds the DERP, STUN and HTTP listeners and serves until ctx is
// cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("veil: listening on %s: %w", s.cfg.ListenAddr, err)
	}
	ln = &limitedListener{Listener: ln, runtime: s.runtime}
	defer ln.Close()
	defer s.derp.Close()
	defer s.closeConnections()
	var stunServer *stunserver.STUNServer
	if s.cfg.STUN {
		host, _, _ := net.SplitHostPort(s.cfg.ListenAddr)
		stunServer = stunserver.New(ctx)
		// UDP 必须先绑定成功再发布就绪，不能只开 TCP 却向客户端广播可用的 STUN。
		if err := stunServer.Listen(net.JoinHostPort(host, strconv.Itoa(s.stunPort()))); err != nil {
			return fmt.Errorf("veil: STUN listener failed: %w", err)
		}
	}
	s.mu.Lock()
	s.listener = ln
	s.addr = ln.Addr()
	s.cancel = cancel
	if stunServer != nil {
		s.stunAddr = stunServer.LocalAddr()
	}
	s.mu.Unlock()

	if stunServer != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := stunServer.Serve(); err != nil && ctx.Err() == nil {
				s.log.Error("veil STUN stopped", "err", err)
				cancel()
			}
		}()
		defer func() {
			cancel()
			<-done
		}()
	}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// DERP connections are long-lived upgrades; no write/idle timeouts
		// may cut them off.
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("veil listening", "addr", ln.Addr().String(), "tls", s.cfg.TLS())
		var err error
		switch {
		case s.acme != nil:
			// TLS-ALPN-01: the ACME validation handshake arrives on this
			// same listener, so no extra port 80 server is needed.
			srv.TLSConfig = s.acme.TLSConfig()
			srv.TLSConfig.MinVersion = tls.VersionTLS12
			err = srv.ServeTLS(ln, "", "")
		case s.cert != nil:
			srv.TLSConfig = &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*s.cert},
			}
			err = srv.ServeTLS(ln, "", "")
		case s.cfg.TLS():
			srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			err = srv.ServeTLS(ln, s.cfg.CertFile, s.cfg.CertKeyFile)
		default:
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("veil shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

// stunPort returns the effective STUN port.
func (s *Server) stunPort() int {
	if s.cfg.STUNPort == 0 {
		return DefaultSTUNPort
	}
	return s.cfg.STUNPort
}

// derpPort returns the effective DERP TCP port.
func (s *Server) derpPort() (int, error) {
	_, port, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		return 0, err
	}
	if port == "" {
		return 443, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("veil: non-numeric port %q", port)
	}
	return n, nil
}

// DERPMap returns a DERP map containing only this node, for the control plane
// to advertise to clients. HostName must be set.
func (s *Server) DERPMap() (*tailcfg.DERPMap, error) {
	if s.cfg.HostName == "" {
		return nil, errors.New("veil: HostName is required to publish a DERP map")
	}
	port, err := s.derpPort()
	if err != nil {
		return nil, err
	}
	regionID := tailcfg.DERPRegionID(s.cfg.RegionID)
	node := &tailcfg.DERPNode{
		Name:             fmt.Sprintf("%da", s.cfg.RegionID),
		RegionID:         regionID,
		HostName:         s.cfg.HostName,
		DERPPort:         port,
		STUNPort:         s.stunPort(),
		InsecureForTests: s.cfg.InsecureForTests,
		// A self-signed certificate is trusted only through this pin: the
		// official client compares it against the certificate the relay
		// presents, so an interception or a swapped relay is refused.
		CertName: s.certPin,
	}
	if !s.cfg.STUN || s.cfg.STUNUnadvertised {
		node.STUNPort = -1
	}
	return &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			regionID: {
				RegionID:   regionID,
				RegionCode: s.cfg.RegionCode,
				RegionName: s.RuntimeConfiguration().RegionName,
				Nodes:      []*tailcfg.DERPNode{node},
			},
		},
		OmitDefaultRegions: true,
	}, nil
}

// Close releases server resources. It is a no-op for a server that never
// served.
func (s *Server) Close() error {
	s.closeConnections()
	s.mu.Lock()
	ln := s.listener
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}
