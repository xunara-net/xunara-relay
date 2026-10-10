package registration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"tailscale.com/atomicfile"
)

type Execution struct {
	ConfigVersion  string `json:"config_version"`
	AppliedVersion string `json:"applied_version,omitempty"`
	Status         string `json:"status"`
	State          string `json:"state"`
	BandwidthLimit int64  `json:"bandwidth_limit"`
	ErrorCode      string `json:"error_code,omitempty"`
}

type RuntimeState struct {
	State          string
	BandwidthLimit int64
}

type runtimeCache struct {
	Format   int           `json:"format"`
	Identity string        `json:"identity"`
	Revision uint64        `json:"revision"`
	Config   *RemoteConfig `json:"config,omitempty"`
	Revoked  bool          `json:"revoked"`
}

type Manager struct {
	mu             sync.Mutex
	path           string
	cache          runtimeCache
	apply          func(RemoteConfig) error
	current        func() RuntimeState
	writeCache     func(string, []byte, os.FileMode) error
	receipt        *Execution
	appliedVersion string
}

var ErrServiceRevoked = errors.New("relay service identity is revoked")

// 缓存只保存身份摘要和版本高水位，不包含凭据，也不证明本进程已执行。
func NewManager(path string, identity Identity, nodeKey string, apply func(RemoteConfig) error, current func() RuntimeState) (*Manager, error) {
	base, err := ControlBaseURL(identity.ControlURL)
	if err != nil || !identity.Valid() || path == "" || nodeKey == "" || apply == nil || current == nil {
		return nil, errors.New("invalid relay runtime manager configuration")
	}
	binding, _ := json.Marshal([]string{identity.RelayID, base, identity.Token, nodeKey})
	digest := sha256.Sum256(binding)
	manager := &Manager{path: path, apply: apply, current: current, writeCache: atomicfile.WriteFile,
		cache: runtimeCache{Format: 1, Identity: hex.EncodeToString(digest[:])}}
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return manager, nil
	}
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() > 64<<10 {
		return nil, errors.New("relay runtime cache is unavailable or insecure")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("relay runtime cache is unreadable")
	}
	var cached runtimeCache
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cached) != nil || cached.Format != 1 || cached.Identity != manager.cache.Identity || !json.Valid(raw) {
		return nil, errors.New("relay runtime cache is invalid or belongs to another identity")
	}
	if cached.Config != nil {
		configuration, revision, err := validateConfiguration(*cached.Config)
		if err != nil || revision != cached.Revision || configuration != *cached.Config || configuration.DesiredState == "revoked" && !cached.Revoked {
			return nil, errors.New("relay runtime cache has invalid configuration")
		}
	} else if cached.Revision != 0 || !cached.Revoked {
		return nil, errors.New("relay runtime cache has no configuration")
	}
	manager.cache = cached
	if cached.Revoked {
		return manager, ErrServiceRevoked
	}
	return manager, nil
}

func validateConfiguration(configuration RemoteConfig) (RemoteConfig, uint64, error) {
	if configuration.ConfigVersion == "" || len(configuration.ConfigVersion) > 64 || strings.IndexFunc(configuration.ConfigVersion, unicode.IsControl) >= 0 || !utf8.ValidString(configuration.ConfigVersion) {
		return RemoteConfig{}, 0, errors.New("invalid relay configuration version")
	}
	revision := configuration.ConfigRevision
	if revision == 0 {
		parsed, err := strconv.ParseUint(configuration.ConfigVersion, 10, 64)
		if err != nil || strconv.FormatUint(parsed, 10) != configuration.ConfigVersion {
			return RemoteConfig{}, 0, errors.New("relay configuration sequence is unavailable")
		}
		revision = parsed
	}
	if revision == 0 || revision > 1<<53-1 || configuration.BandwidthLimit < -1 || configuration.BandwidthLimit > 1<<53-1 || len(configuration.RegionName) > 128 || !utf8.ValidString(configuration.RegionName) || strings.IndexFunc(configuration.RegionName, unicode.IsControl) >= 0 {
		return RemoteConfig{}, 0, errors.New("invalid relay configuration")
	}
	switch configuration.DesiredState {
	case "online", "maintenance", "disabled", "revoked":
	default:
		return RemoteConfig{}, 0, errors.New("invalid relay configuration state")
	}
	configuration.ConfigRevision = revision
	return configuration, revision, nil
}

func (manager *Manager) persist(cache runtimeCache) error {
	raw, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return manager.writeCache(manager.path, append(raw, '\n'), 0o600)
}

func (manager *Manager) failure(version, code string) error {
	actual := manager.current()
	manager.receipt = &Execution{version, manager.appliedVersion, "failed", actual.State, actual.BandwidthLimit, code}
	return errors.New("relay configuration execution failed: " + code)
}

func (manager *Manager) Apply(configuration RemoteConfig) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	normalized, revision, err := validateConfiguration(configuration)
	if err != nil {
		manager.receipt = nil
		return errors.New("relay configuration execution failed: config_invalid")
	}
	if manager.cache.Revoked && (manager.cache.Config == nil || normalized != *manager.cache.Config || normalized.DesiredState != "revoked") {
		return ErrServiceRevoked
	}
	if revision < manager.cache.Revision || revision == manager.cache.Revision && manager.cache.Config != nil && normalized != *manager.cache.Config {
		manager.receipt = nil
		return errors.New("relay configuration execution failed: version_conflict")
	}
	if manager.receipt != nil && manager.receipt.Status == "applied" && manager.cache.Config != nil && normalized == *manager.cache.Config {
		return nil
	}
	next := manager.cache
	next.Config, next.Revision, next.Revoked = &normalized, revision, normalized.DesiredState == "revoked"
	manager.cache = next
	if err := manager.persist(next); err != nil {
		// 磁盘故障不能让停用指令失效；先限制数据面，再上报持久化失败。
		if normalized.DesiredState != "online" {
			if applyErr := manager.apply(normalized); applyErr != nil {
				return manager.failure(normalized.ConfigVersion, "apply_failed")
			}
			if normalized.DesiredState == "revoked" {
				manager.cache.Revoked = true
			}
		}
		return manager.failure(normalized.ConfigVersion, "cache_write_failed")
	}
	if err := manager.apply(normalized); err != nil {
		return manager.failure(normalized.ConfigVersion, "apply_failed")
	}
	manager.appliedVersion = normalized.ConfigVersion
	actual := manager.current()
	manager.receipt = &Execution{normalized.ConfigVersion, manager.appliedVersion, "applied", actual.State, actual.BandwidthLimit, ""}
	return nil
}

func (manager *Manager) Receipt() *Execution {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.receipt == nil {
		return nil
	}
	receipt := *manager.receipt
	return &receipt
}

// 401/撤销是服务身份终态，不是普通网络故障；先停数据面，再尽力落盘。
func (manager *Manager) Revoke() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.cache.Revoked = true
	if err := manager.apply(RemoteConfig{DesiredState: "revoked"}); err != nil {
		return errors.New("relay revocation execution failed")
	}
	if err := manager.persist(manager.cache); err != nil {
		return errors.New("relay revocation cache write failed")
	}
	return nil
}
