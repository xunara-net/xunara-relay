package relay

import (
	"encoding/json"
	"errors"
	"net"
	"sync"

	"golang.org/x/time/rate"
)

type RuntimeConfig struct {
	DesiredState   string
	BandwidthLimit int64
	RegionName     string
}

type Statistics struct {
	ConnectedClients int   `json:"gauge_current_connections"`
	BytesIn          int64 `json:"bytes_received"`
	BytesOut         int64 `json:"bytes_sent"`
}

type runtimeControl struct {
	mu            sync.Mutex
	applyMutex    sync.Mutex
	configuration RuntimeConfig
	burst         int
	connections   map[*limitedConn]struct{}
}

func newRuntimeControl(configuration Config) *runtimeControl {
	return &runtimeControl{
		configuration: RuntimeConfig{"online", configuration.BandwidthLimit, configuration.RegionName},
		burst:         configuration.bandwidthBurst(), connections: make(map[*limitedConn]struct{}),
	}
}

func runtimeLimit(configuration RuntimeConfig) rate.Limit {
	if configuration.BandwidthLimit == 0 {
		return rate.Inf
	}
	return rate.Limit(configuration.BandwidthLimit)
}

func (runtime *runtimeControl) track(connection net.Conn) *limitedConn {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	limited := newLimitedConn(connection, rate.NewLimiter(runtimeLimit(runtime.configuration), runtime.burst))
	limited.onClose = func() {
		runtime.mu.Lock()
		delete(runtime.connections, limited)
		runtime.mu.Unlock()
	}
	runtime.connections[limited] = struct{}{}
	return limited
}

func (server *Server) RuntimeConfiguration() RuntimeConfig {
	server.runtime.mu.Lock()
	defer server.runtime.mu.Unlock()
	return server.runtime.configuration
}

// 托管进程先失败关闭；磁盘缓存不是本次启动的授权依据。
func (server *Server) AwaitControlAuthorization() {
	server.runtime.applyMutex.Lock()
	defer server.runtime.applyMutex.Unlock()
	server.runtime.mu.Lock()
	if server.runtime.configuration.DesiredState == "revoked" {
		server.runtime.mu.Unlock()
		return
	}
	server.runtime.configuration.DesiredState = "pending"
	server.runtime.mu.Unlock()
	server.closeConnections()
}

// Core 只认识运行时配置，不依赖控制面注册、套餐或用户身份。
func (server *Server) ApplyRuntimeConfiguration(configuration RuntimeConfig) error {
	switch configuration.DesiredState {
	case "online", "maintenance", "disabled", "revoked":
	default:
		return errors.New("invalid relay runtime state")
	}
	if configuration.BandwidthLimit < -1 || configuration.BandwidthLimit > 1<<53-1 {
		return errors.New("invalid relay bandwidth limit")
	}
	effective := server.cfg
	switch configuration.BandwidthLimit {
	case 0:
		configuration.BandwidthLimit = effective.BandwidthLimit
	case -1:
		configuration.BandwidthLimit = 0
	default:
		effective.BandwidthLimit = configuration.BandwidthLimit
		effective.BandwidthBurst = 0
	}
	if configuration.BandwidthLimit == 0 {
		effective.BandwidthLimit = 0
	}
	if configuration.RegionName == "" {
		configuration.RegionName = server.cfg.RegionName
	}
	server.runtime.applyMutex.Lock()
	defer server.runtime.applyMutex.Unlock()
	server.runtime.mu.Lock()
	if server.runtime.configuration.DesiredState == "revoked" && configuration.DesiredState != "revoked" {
		server.runtime.mu.Unlock()
		return errors.New("revoked relay cannot be reactivated")
	}
	server.runtime.configuration = configuration
	server.runtime.burst = effective.bandwidthBurst()
	for connection := range server.runtime.connections {
		connection.setRate(runtimeLimit(configuration), server.runtime.burst)
	}
	server.runtime.mu.Unlock()
	// DERP Server.Close 是永久关闭，维护/停用不能使用它；关闭被追踪的 TCP 即可。
	if configuration.DesiredState == "disabled" || configuration.DesiredState == "revoked" {
		server.closeConnections()
	}
	return nil
}

func (server *Server) closeConnections() {
	server.runtime.mu.Lock()
	connections := make([]*limitedConn, 0, len(server.runtime.connections))
	for connection := range server.runtime.connections {
		connections = append(connections, connection)
	}
	server.runtime.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

// 采用上游 DERP 计数器，不把 TLS/HTTP 连接数伪称为已注册客户端。
func (server *Server) Statistics() (Statistics, error) {
	var statistics Statistics
	err := json.Unmarshal([]byte(server.metrics.String()), &statistics)
	return statistics, err
}
