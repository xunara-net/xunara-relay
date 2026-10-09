// Command xunara-relay is the Xunara Relay server.
//
// It speaks the DERP and STUN protocols of the official Tailscale clients and
// can be wired to the control plane's admission endpoint so that only node
// keys of this deployment are relayed. With -control-url it also enrolls with
// the Xunara control plane and reports heartbeats, which is what makes a relay
// show up in the console instead of running as an anonymous DERP node.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-relay/registration"
	"github.com/xunara-net/xunara-relay/relay"
)

// version is the relay build version; release builds inject it with
// -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		showVersion = flag.Bool("version", false, "print the version and exit")
		listen      = flag.String("listen", ":3340", "TCP address for the DERP/HTTP server")
		hostname    = flag.String("hostname", "", "publicly reachable hostname of this node (required with -derp-map-out)")
		stateDir    = flag.String("state-dir", "veil-data", "directory for persistent state (the DERP node key)")
		keyFile     = flag.String("key-file", "", "DERP node key file (default <state-dir>/derp.key)")
		runSTUN     = flag.Bool("stun", true, "run a STUN server for endpoint discovery")
		stunPort    = flag.Int("stun-port", relay.DefaultSTUNPort, "UDP port for STUN")
		verifyURL   = flag.String("verify-url", "", "control plane admission URL (e.g. http://127.0.0.1:8080/derp/admit); empty admits any node key")
		meshKeyEnv  = flag.String("mesh-key-env", "", "environment variable holding the 64-hex DERP mesh key (trusts other Veil nodes); empty disables meshing")
		bandwidth   = flag.Int64("bandwidth-limit", 0, "per-connection bandwidth limit in bytes per second (0: unlimited)")
		bandwidthB  = flag.Int("bandwidth-burst", 0, "token bucket size in bytes for -bandwidth-limit (0: derived from the limit)")
		certFile    = flag.String("cert-file", "", "TLS certificate file (enables TLS with -cert-key-file)")
		certKeyFile = flag.String("cert-key-file", "", "TLS private key file")
		certMode    = flag.String("cert-mode", "", `TLS certificate mode: "manual" (uses -cert-file/-cert-key-file), "letsencrypt" (ACME via TLS-ALPN-01; requires -hostname and -cert-dir) or "selfsigned" (generates a certificate for a relay reached by IP; its SHA-256 pin is published in generated DERP maps)`)
		certDir     = flag.String("cert-dir", "", "certificate state directory: the ACME cache with -cert-mode=letsencrypt, the generated pair with -cert-mode=selfsigned (default <state-dir>)")
		acmeEmail   = flag.String("acme-email", "", "contact email for the ACME account (optional)")
		insecure    = flag.Bool("insecure-for-tests", false, "mark the node InsecureForTests in generated DERP maps; local plain-HTTP tests only")
		regionID    = flag.Int("region-id", relay.DefaultRegionID, "DERP region ID in generated maps")
		regionCode  = flag.String("region-code", "veil", "DERP region code; name this relay in the console")
		regionName  = flag.String("region-name", "Xunara Relay", "human-readable region name")
		derpMapOut  = flag.String("derp-map-out", "", "write a single-node tailcfg.DERPMap JSON here (\"-\" for stdout); pass it to xunarad -derp-map")
		derpMapOnly = flag.Bool("derp-map-only", false, "write -derp-map-out and exit without serving; provisioning only")
		logLevel    = flag.String("log-level", "info", "log level: debug|info|warn|error")

		controlURL   = flag.String("control-url", "", "Xunara control plane base URL (e.g. https://control.example.com) for a managed relay; empty runs a standalone DERP relay")
		enrollEnv    = flag.String("enroll-token-env", "", "environment variable holding the one-time relay enrollment token; read once, when no identity exists yet")
		identityFile = flag.String("identity-file", "", "relay identity file (default <state-dir>/relay-identity.json, mode 0600)")
		relayName    = flag.String("relay-name", "", "relay name shown in the console (default: the hostname)")
		visibility   = flag.String("relay-visibility", registration.VisibilityPrivate, `relay visibility: "private", "organization" or "public"`)
		heartbeat    = flag.Duration("heartbeat-interval", time.Minute, "how often a managed relay reports to the control plane")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("xunara-relay " + version)
		return
	}

	logger := newLogger(*logLevel)

	// The mesh key is a shared secret: it is read from the environment, never
	// from argv (AGENTS.md section 8). A named-but-empty variable is refused,
	// so a misconfigured deployment cannot silently run without it.
	var meshKey string
	if *meshKeyEnv != "" {
		meshKey = os.Getenv(*meshKeyEnv)
		if meshKey == "" {
			logger.Error("mesh key environment variable is unset or empty", "env", *meshKeyEnv)
			os.Exit(1)
		}
	}

	identityPath := *identityFile
	if identityPath == "" {
		identityPath = filepath.Join(*stateDir, "relay-identity.json")
	}
	identity, haveIdentity, err := registration.LoadIdentity(identityPath)
	if err != nil {
		logger.Error("reading relay identity", "err", err)
		os.Exit(1)
	}
	managedURL := *controlURL
	if haveIdentity {
		managedURL = identity.ControlURL
	}
	*verifyURL, err = managedAdmissionURL(managedURL, *verifyURL)
	if err != nil {
		logger.Error("invalid managed relay admission configuration", "err", err)
		os.Exit(1)
	}
	if managedURL != "" && *certMode == "" && !*insecure {
		logger.Error("managed relay requires a TLS certificate mode; choose selfsigned, manual or letsencrypt")
		os.Exit(1)
	}
	srv, err := relay.New(relay.Config{
		ListenAddr:       *listen,
		HostName:         *hostname,
		StateDir:         *stateDir,
		KeyFile:          *keyFile,
		STUN:             *runSTUN,
		STUNPort:         *stunPort,
		VerifyURL:        *verifyURL,
		MeshKey:          meshKey,
		BandwidthLimit:   *bandwidth,
		BandwidthBurst:   *bandwidthB,
		CertFile:         *certFile,
		CertKeyFile:      *certKeyFile,
		CertMode:         *certMode,
		CertDir:          *certDir,
		ACMEEmail:        *acmeEmail,
		InsecureForTests: *insecure,
		RegionID:         *regionID,
		RegionCode:       *regionCode,
		RegionName:       *regionName,
		Logger:           logger,
	})
	if err != nil {
		logger.Error("initializing veil", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	started := time.Now()
	if !haveIdentity && *controlURL != "" {
		token := ""
		if *enrollEnv != "" {
			token = os.Getenv(*enrollEnv)
			if token == "" {
				logger.Error("enrollment token environment variable is unset or empty", "env", *enrollEnv)
				os.Exit(1)
			}
		}
		if token == "" {
			// Fail closed: a managed relay without an identity must not
			// invent one, and silently serving as a standalone node would
			// hide the misconfiguration.
			logger.Error("managed relay has no identity and no enrollment token; set -enroll-token-env or drop -control-url")
			os.Exit(1)
		}
		name := *relayName
		if name == "" {
			if host, err := os.Hostname(); err == nil {
				name = host
			} else {
				name = *regionCode
			}
		}
		derpPort, err := relayConfigDERPPort(*listen)
		if err != nil {
			logger.Error("deriving the DERP port", "err", err)
			os.Exit(1)
		}
		client := &registration.Client{ControlURL: *controlURL, Token: token, UserAgent: "xunara-relay/" + version}
		derpMap, mapErr := srv.DERPMap()
		if mapErr != nil {
			logger.Error("preparing managed DERP map", "err", mapErr)
			os.Exit(1)
		}
		enrolled, err := client.Enroll(context.Background(), registration.EnrollRequest{
			Name:       name,
			RegionCode: *regionCode,
			RegionName: *regionName,
			RegionID:   *regionID,
			CertName:   derpMap.Regions[tailcfg.DERPRegionID(*regionID)].Nodes[0].CertName,
			HostName:   *hostname,
			NodeKey:    srv.PublicKey().String(),
			Version:    version,
			DERPPort:   derpPort,
			STUNPort:   *stunPort,
			Visibility: *visibility,
		})
		if err != nil {
			logger.Error("relay enrollment failed", "err", err)
			os.Exit(1)
		}
		if err := enrolled.Save(identityPath); err != nil {
			logger.Error("storing relay identity", "err", err)
			os.Exit(1)
		}
		identity, haveIdentity = enrolled, true
		logger.Info("relay enrolled", "relay_id", enrolled.RelayID, "control", enrolled.ControlURL, "identity_file", identityPath)
	}

	if *derpMapOut != "" {
		if err := writeDERPMap(srv, *derpMapOut); err != nil {
			logger.Error("writing DERP map", "err", err)
			os.Exit(1)
		}
	}
	if *derpMapOnly {
		if *derpMapOut == "" {
			logger.Error("-derp-map-only needs -derp-map-out")
			os.Exit(2)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if haveIdentity {
		client := &registration.Client{
			ControlURL: identity.ControlURL,
			Token:      identity.Token,
			UserAgent:  "xunara-relay/" + version,
		}
		go client.RunHeartbeats(ctx, *heartbeat,
			func() registration.Status {
				return registration.Status{
					Version:       version,
					Healthy:       true,
					UptimeSeconds: int64(time.Since(started).Seconds()),
				}
			},
			func(cfg registration.RemoteConfig) {
				logger.Info("relay configuration updated",
					"config_version", cfg.ConfigVersion, "desired_state", cfg.DesiredState)
			},
			func(err error) { logger.Warn("relay heartbeat failed", "err", err) },
		)
	}

	if err := srv.Serve(ctx); err != nil {
		logger.Error("veil error", "err", err)
		os.Exit(1)
	}
}

func managedAdmissionURL(controlURL, explicit string) (string, error) {
	if controlURL == "" {
		return explicit, nil
	}
	base, err := registration.ControlBaseURL(controlURL)
	if err != nil {
		return "", err
	}
	if explicit != "" {
		return explicit, nil
	}
	// 私有中继重启后仍使用持久服务身份对应的租户准入，不退回开放代理。
	return base + "/derp/admit", nil
}

// relayConfigDERPPort derives the numeric DERP port from the listen address.
// Enrollment reports it to the control plane so the generated DERP map points
// clients at the right port; a port of 0 (":3340" is stripped to "") means the
// control plane falls back to the default.
func relayConfigDERPPort(listen string) (int, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("parsing -listen %q: %w", listen, err)
	}
	if port == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parsing port in -listen %q: %w", listen, err)
	}
	return n, nil
}

// writeDERPMap renders the server's single-node DERP map to path, or stdout
// when path is "-".
func writeDERPMap(srv *relay.Server, path string) error {
	m, err := srv.DERPMap()
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	if path == "-" {
		_, err := os.Stdout.Write(blob)
		return err
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
