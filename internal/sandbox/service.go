package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	"example.com/sandbox-demo/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/coreos/go-iptables/iptables"
)

const (
	DefaultNamespace       = "sandbox-demo"
	DefaultContainerdAddr  = "/run/firecracker-containerd/containerd.sock"
	DefaultStateBaseDir    = "/var/lib/sandboxd/sandboxes"
	DefaultLockDir         = "/var/lib/sandboxd/locks"
	DefaultBridgeInterface = "fc-br0"
	DefaultSubnetCIDR      = "10.89.0.0/16"
	DefaultCNIConfPath     = "/etc/cni/net.d/20-fcnet.conflist"
	DefaultReadyTimeout    = 8 * time.Second
	DefaultReconcileEvery  = 15 * time.Second
)

type Config struct {
	ContainerdAddress string
	Namespace         string
	StateBaseDir      string
	LockDir           string
	BridgeInterface   string
	SubnetCIDR        string
	ReconcileInterval time.Duration
}

type Service struct {
	client         *containerd.Client
	ipt            *iptables.IPTables
	store          *store.FileStore
	cfg            Config
	namespace      string
	bridgeIF       string
	cidr           string
	containerdAddr string
	lockDir        string
}

func DefaultConfig() Config {
	addr := os.Getenv("SANDBOX_CONTAINERD_ADDRESS")
	if addr == "" {
		addr = DefaultContainerdAddr
	}

	return Config{ContainerdAddress: addr, Namespace: DefaultNamespace, StateBaseDir: DefaultStateBaseDir, LockDir: DefaultLockDir, BridgeInterface: DefaultBridgeInterface, SubnetCIDR: DefaultSubnetCIDR, ReconcileInterval: DefaultReconcileEvery}
}

func New(ctx context.Context, cfg Config) (*Service, error) {
	_ = ctx
	if cfg.ContainerdAddress == "" {
		cfg.ContainerdAddress = DefaultContainerdAddr
	}

	if cfg.Namespace == "" {
		cfg.Namespace = DefaultNamespace
	}

	if cfg.StateBaseDir == "" {
		cfg.StateBaseDir = DefaultStateBaseDir
	}

	if cfg.LockDir == "" {
		cfg.LockDir = DefaultLockDir
	}

	if cfg.BridgeInterface == "" {
		cfg.BridgeInterface = DefaultBridgeInterface
	}

	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = DefaultSubnetCIDR
	}

	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = DefaultReconcileEvery
	}

	client, err := containerd.New(cfg.ContainerdAddress)
	if err != nil {
		return nil, err
	}

	ipt, err := iptables.New(iptables.Timeout(5))
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	if err := network.EnsureBridgeNetfilter(); err != nil {
		_ = client.Close()
		return nil, err
	}

	st, err := store.NewFileStore(cfg.StateBaseDir)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	if err := network.EnsureGlobalChains(ipt, csvEnv("SANDBOX_FORWARD_HOOK_CHAINS", []string{"FORWARD", "DOCKER-USER"})); err != nil {
		_ = client.Close()
		return nil, err
	}

	s := &Service{client: client, ipt: ipt, store: st, cfg: cfg, namespace: cfg.Namespace, bridgeIF: cfg.BridgeInterface, cidr: cfg.SubnetCIDR, containerdAddr: cfg.ContainerdAddress, lockDir: cfg.LockDir}
	if err := os.MkdirAll(s.lockDir, 0o755); err != nil {
		_ = client.Close()
		return nil, err
	}

	return s, nil
}

func (s *Service) Close() error { return s.client.Close() }

func (s *Service) CreateSandbox(ctx context.Context, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	unlock, err := s.acquireSandboxLock(req.ID)
	if err != nil {
		return nil, err
	}

	defer unlock()
	unlockPorts, err := s.acquireSandboxLock("_ports")
	if err != nil {
		return nil, err
	}
	defer unlockPorts()

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if _, err := s.store.Load(req.ID); err == nil {
		return nil, fmt.Errorf("sandbox already exists: %s", req.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := s.ensureHostPortsAvailable(req.ID, req.Ports); err != nil {
		return nil, err
	}

	ctx = namespaces.WithNamespace(ctx, s.namespace)
	now := time.Now().UTC()
	sbx := &model.Sandbox{ID: req.ID, Phase: "creating", Namespace: s.namespace, Egress: req.Egress, BridgeName: s.bridgeIF, SubnetCIDR: s.cidr, CNIConfPath: DefaultCNIConfPath, Containers: map[string]model.ContainerState{}, CreatedAt: now, UpdatedAt: now}
	sbx.Ports = append(sbx.Ports, req.Ports...)
	created := false

	defer func() {
		if !created {
			sbx.Phase = "error"
			sbx.UpdatedAt = time.Now().UTC()
			_ = s.deleteSandboxFromState(ctx, sbx)
		}
	}()

	if err := s.createVM(ctx, sbx.ID, len(req.Containers)); err != nil {
		return nil, err
	}

	for _, c := range req.Containers {
		st, err := s.createContainer(ctx, sbx.ID+"-"+c.Name, c.Name, c.Image, c.Args, c.Env, c.WorkDir, withDefaultLimits(c.Limits), sbx.ID)
		if err != nil {
			sbx.Error = err.Error()
			return nil, err
		}

		sbx.Containers[c.Name] = st
	}

	ip, err := s.resolveSandboxIP(ctx, sbx.ID)
	if err != nil {
		return nil, err
	}

	sbx.IP = ip
	if err := s.applySandboxNetworkPolicy(sbx); err != nil {
		return nil, err
	}

	if len(req.Ports) > 0 {
		pub, hostPorts := toHostPortRules(req.Ports)
		if err := network.ApplyHostPortDNAT(s.ipt, ip, pub, hostPorts); err != nil {
			return nil, fmt.Errorf("apply hostPort rules: %w", err)
		}
	}

	if err := s.waitSandboxReady(ctx, sbx); err != nil {
		return nil, err
	}

	s.refreshSandboxRuntimeState(ctx, sbx)
	sbx.Phase = "running"
	sbx.Error = ""
	sbx.UpdatedAt = time.Now().UTC()

	if err := s.store.Save(sbx); err != nil {
		return nil, err
	}

	created = true
	return sbx, nil
}

func (s *Service) DeleteSandbox(ctx context.Context, sandboxID string) error {
	unlock, err := s.acquireSandboxLock(sandboxID)
	if err != nil {
		return err
	}
	defer unlock()

	ctx = namespaces.WithNamespace(ctx, s.namespace)
	sbx, err := s.store.Load(sandboxID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	sbx.Phase = "deleting"
	sbx.UpdatedAt = time.Now().UTC()

	_ = s.store.Save(sbx)
	return s.deleteSandboxFromState(ctx, sbx)
}

func (s *Service) ListSandboxes(_ context.Context) ([]*model.Sandbox, error) {
	ctx := namespaces.WithNamespace(context.Background(), s.namespace)
	all, err := s.store.List()
	if err != nil {
		return nil, err
	}

	for _, sbx := range all {
		s.refreshSandboxRuntimeState(ctx, sbx)
	}

	return all, nil
}

func (s *Service) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	sbx, err := s.store.Load(id)
	if err != nil {
		return nil, err
	}

	s.refreshSandboxRuntimeState(namespaces.WithNamespace(ctx, s.namespace), sbx)
	return sbx, nil
}

func (s *Service) ensureHostPortsAvailable(sandboxID string, requested []model.PortMapping) error {
	if len(requested) == 0 {
		return nil
	}

	type owner struct{ sandboxID, proto string }

	used := map[int]owner{}
	all, err := s.store.List()
	if err != nil {
		return err
	}

	for _, sb := range all {
		if sb.ID == sandboxID {
			continue
		}

		for _, p := range sb.Ports {
			proto := strings.ToLower(strings.TrimSpace(p.Protocol))
			if proto == "" {
				proto = "tcp"
			}

			used[p.HostPort] = owner{sandboxID: sb.ID, proto: proto}
		}
	}

	for _, p := range requested {
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		if proto == "" {
			proto = "tcp"
		}

		if o, ok := used[p.HostPort]; ok && o.proto == proto {
			return fmt.Errorf("host port already in use: %d/%s (sandbox %s)", p.HostPort, proto, o.sandboxID)
		}
	}

	return nil
}

func (s *Service) waitSandboxReady(ctx context.Context, sbx *model.Sandbox) error {
	deadline := time.Now().Add(DefaultReadyTimeout)
	for time.Now().Before(deadline) {
		allRunning := true
		for _, c := range sbx.Containers {
			ctr, err := s.client.LoadContainer(ctx, c.ID)
			if err != nil {
				allRunning = false
				break
			}

			task, err := ctr.Task(ctx, nil)
			if err != nil {
				allRunning = false
				break
			}

			st, err := task.Status(ctx)
			if err != nil || string(st.Status) != "running" {
				allRunning = false
				break
			}
		}

		if allRunning {
			return nil
		}

		time.Sleep(150 * time.Millisecond)
	}

	return fmt.Errorf("sandbox %s did not become ready before timeout", sbx.ID)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.ToUpper(strings.TrimSpace(p)))
	}

	return out
}

func csvEnv(key string, def []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return append([]string(nil), def...)
	}

	out := make([]string, 0)
	for _, p := range splitCSV(raw) {
		if p != "" {
			out = append(out, p)
		}
	}

	if len(out) == 0 {
		return append([]string(nil), def...)
	}

	return out
}
