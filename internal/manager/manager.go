package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	sbruntime "example.com/sandbox-demo/internal/runtime"
	"example.com/sandbox-demo/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containernetworking/cni/libcni"
	"github.com/coreos/go-iptables/iptables"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	DefaultNS  = "sandbox-demo"
	PauseImage = "registry.k8s.io/pause:3.10"
)

type Manager struct {
	client         *containerd.Client
	cni            *libcni.CNIConfig
	netConf        *libcni.NetworkConfigList
	ipt            *iptables.IPTables
	store          store.Store
	bridgeIF       string
	cidr           string
	runtimeProfile sbruntime.Profile
	lockDir        string
	stopReconcile  chan struct{}
	reconcileWG    sync.WaitGroup
}

func New(ctx context.Context, cniConfPath string) (*Manager, error) {
	_ = ctx
	addr := os.Getenv("SANDBOX_CONTAINERD_ADDRESS")
	if addr == "" {
		addr = "/run/containerd/containerd.sock"
	}

	client, err := containerd.New(addr)
	if err != nil {
		return nil, err
	}

	profileName := os.Getenv("SANDBOX_RUNTIME_PROFILE")
	if profileName == "" {
		profileName = os.Getenv("SANDBOX_RUNTIME")
	}

	profile, err := sbruntime.Resolve(profileName)
	if err != nil {
		return nil, err
	}

	cni := libcni.NewCNIConfig([]string{"/opt/cni/bin"}, nil)
	netConf, err := libcni.ConfListFromFile(cniConfPath)
	if err != nil {
		return nil, err
	}

	ipt, err := iptables.New(iptables.Timeout(5))
	if err != nil {
		return nil, err
	}

	// Bridge L2 traffic must hit iptables FORWARD for sandbox isolation rules
	// to be effective across different sandbox IPs on the same bridge.
	if err := network.EnsureBridgeNetfilter(); err != nil {
		return nil, err
	}

	st, err := store.NewFileStore("/var/lib/sandbox-demo/state")
	if err != nil {
		return nil, err
	}

	if err := network.EnsureGlobalChains(ipt, csvEnv("SANDBOX_FORWARD_HOOK_CHAINS", []string{"FORWARD", "DOCKER-USER"})); err != nil {
		return nil, err
	}

	if err := os.MkdirAll("/var/lib/sandbox-demo/state", 0o755); err != nil {
		return nil, err
	}

	m := &Manager{
		client:         client,
		cni:            cni,
		netConf:        netConf,
		ipt:            ipt,
		store:          st,
		bridgeIF:       "sand0",
		cidr:           "10.88.0.0/16",
		runtimeProfile: profile,
		lockDir:        "/var/lib/sandbox-demo/locks",
		stopReconcile:  make(chan struct{}),
	}
	if err := os.MkdirAll(m.lockDir, 0o755); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) Close() error {
	close(m.stopReconcile)
	m.reconcileWG.Wait()

	return m.client.Close()
}

func (m *Manager) StartReconcileLoop(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}

	m.reconcileWG.Add(1)
	go func() {
		defer m.reconcileWG.Done()
		tk := time.NewTicker(interval)
		defer tk.Stop()
		_ = m.Reconcile(context.Background())

		for {
			select {
			case <-m.stopReconcile:
				return
			case <-tk.C:
				_ = m.Reconcile(context.Background())
			}
		}
	}()
}

func (m *Manager) CreateSandbox(ctx context.Context, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	// Serialize operations per sandbox ID to avoid concurrent create/delete races.
	unlock, err := m.acquireSandboxLock(req.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if _, err := m.store.Load(req.ID); err == nil {
		return nil, fmt.Errorf("sandbox already exists: %s", req.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	sbx := &model.Sandbox{ID: req.ID, Namespace: DefaultNS, Egress: req.Egress, BridgeName: m.bridgeIF, SubnetCIDR: m.cidr, CNIConfPath: "/etc/cni/net.d/10-sandbox-demo.conflist", Containers: map[string]model.ContainerState{}, CreatedAt: time.Now().UTC()}
	sbx.Ports = append(sbx.Ports, req.Ports...)

	// Pause container owns sandbox netns; app containers join this namespace.
	pause, err := m.createContainer(ctx, sbx.ID+"-pause", "pause", PauseImage, []string{}, nil, "", model.ResourceLimits{MemoryBytes: 64 * 1024 * 1024, CPUPeriod: 100000, CPUQuota: 30000, PidsLimit: 64}, "")
	if err != nil {
		return nil, err
	}

	sbx.Pause = pause

	// Pin /proc/<pid>/ns/net to stable path for CNI DEL and later cleanup.
	netnsPath, err := network.BindMountNetNS(sbx.Pause.TaskPID, sbx.ID)
	if err != nil {
		return nil, err
	}

	sbx.NetNSPath = netnsPath

	// CNI allocates veth/IP/route/hostPort for the sandbox netns.
	cniPorts := toCNIPorts(req.Ports)
	cniResult, err := network.AddSandboxNetwork(ctx, m.cni, m.netConf, sbx.ID, netnsPath, cniPorts)
	if err != nil {
		return nil, err
	}

	ip, err := network.ParseIPv4(cniResult)
	if err != nil {
		return nil, err
	}

	sbx.IP = ip
	sbx.GatewayIP = network.GatewayIPFromResult(cniResult)

	// Apply per-sandbox filter policy after IP allocation.
	if err := network.ApplySandboxRules(m.ipt, sbx.ID, sbx.IP, m.cidr, m.bridgeIF, sbx.Egress, toPublishedPorts(req.Ports)); err != nil {
		return nil, err
	}

	for _, c := range req.Containers {
		st, err := m.createContainer(ctx, sbx.ID+"-"+c.Name, c.Name, c.Image, c.Args, c.Env, c.WorkDir, withDefaultLimits(c.Limits), netnsPath)
		if err != nil {
			return nil, err
		}

		sbx.Containers[c.Name] = st
	}

	m.refreshSandboxRuntimeState(ctx, sbx)
	if err := m.store.Save(sbx); err != nil {
		return nil, err
	}

	return sbx, nil
}

func (m *Manager) DeleteSandbox(ctx context.Context, sandboxID string) error {
	// Same per-sandbox lock model as create; delete must be race-free.
	unlock, err := m.acquireSandboxLock(sandboxID)
	if err != nil {
		return err
	}
	defer unlock()

	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	sbx, err := m.store.Load(sandboxID)
	if err != nil {
		return err
	}

	var errs []error
	// Delete workload containers first, then network, then pause/netns/state.
	for _, name := range sortedContainerNames(sbx.Containers) {
		if e := m.stopAndDeleteContainer(ctx, sbx.Containers[name].ID, sbx.Containers[name].SnapshotKey); e != nil {
			errs = append(errs, e)
		}
	}

	if e := network.DelSandboxNetwork(ctx, m.cni, m.netConf, sbx.ID, sbx.NetNSPath, toCNIPorts(sbx.Ports)); e != nil {
		errs = append(errs, e)
	}

	network.DeleteSandboxRules(m.ipt, sbx.ID, sbx.IP, sbx.BridgeName, toPublishedPorts(sbx.Ports))
	if e := m.stopAndDeleteContainer(ctx, sbx.Pause.ID, sbx.Pause.SnapshotKey); e != nil {
		errs = append(errs, e)
	}

	if e := network.UnmountNetNS(sbx.NetNSPath); e != nil {
		errs = append(errs, e)
	}

	if e := m.store.Delete(sandboxID); e != nil {
		errs = append(errs, e)
	}

	return errors.Join(errs...)
}

func (m *Manager) ListSandboxes(_ context.Context) ([]*model.Sandbox, error) {
	ctx := namespaces.WithNamespace(context.Background(), DefaultNS)
	all, err := m.store.List()
	if err != nil {
		return nil, err
	}

	for _, sbx := range all {
		m.refreshSandboxRuntimeState(ctx, sbx)
	}

	return all, nil
}

func (m *Manager) Reconcile(ctx context.Context) error {
	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	all, err := m.store.List()
	if err != nil {
		return err
	}

	var errs []error
	for _, sbx := range all {
		// Reconcile works best-effort per sandbox to avoid one failure blocking all.
		unlock, lerr := m.acquireSandboxLock(sbx.ID)
		if lerr != nil {
			errs = append(errs, lerr)
			continue
		}

		healthy := m.isSandboxHealthy(ctx, sbx)
		if !healthy {
			// Drifted or partially-broken sandboxes are force-cleaned from state.
			if e := m.deleteSandboxFromState(ctx, sbx); e != nil {
				errs = append(errs, fmt.Errorf("reconcile %s: %w", sbx.ID, e))
			}
		}

		unlock()
	}

	return errors.Join(errs...)
}

func (m *Manager) acquireSandboxLock(id string) (func(), error) {
	lockPath := filepath.Join(m.lockDir, id+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}

	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (m *Manager) createContainer(ctx context.Context, id, name, image string, args, env []string, workDir string, lim model.ResourceLimits, netnsPath string) (model.ContainerState, error) {
	img, err := m.client.Pull(ctx, normalizeImage(image), containerd.WithPullUnpack)
	if err != nil {
		return model.ContainerState{}, err
	}

	snap := id + "-snapshot"
	mounts := []specs.Mount{
		{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw", "nosuid", "nodev", "size=64m"}},
		{Destination: "/run", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw", "nosuid", "nodev", "size=64m"}},
		{Destination: "/var/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw", "nosuid", "nodev", "size=64m"}},
		{Destination: "/var/cache", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw", "nosuid", "nodev", "size=64m"}},
		{Destination: "/var/log", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw", "nosuid", "nodev", "size=32m"}},
	}

	// In systemd-resolved hosts, /etc/resolv.conf often points to 127.0.0.53
	// (host-local stub) which is unreachable inside sandbox netns.
	if resolvPath := containerResolvConfPath(); resolvPath != "" {
		mounts = append(mounts, specs.Mount{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      resolvPath,
			Options:     []string{"rbind", "ro"},
		})
	}

	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithNoNewPrivileges,
		oci.WithCapabilities([]string{}),
		oci.WithMaskedPaths([]string{"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"}),
		oci.WithReadonlyPaths([]string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}),
		oci.WithMemoryLimit(uint64(lim.MemoryBytes)),
		oci.WithPidsLimit(lim.PidsLimit),
		oci.WithCPUCFS(lim.CPUQuota, lim.CPUPeriod),
		oci.WithMounts(mounts),
	}

	if len(args) > 0 {
		specOpts = append(specOpts, oci.WithProcessArgs(args...))
	}

	if len(env) > 0 {
		specOpts = append(specOpts, oci.WithEnv(env))
	}

	if workDir != "" {
		specOpts = append(specOpts, oci.WithProcessCwd(workDir))
	}

	if netnsPath != "" {
		specOpts = append(specOpts, oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: netnsPath}))
	}

	ctr, err := m.client.NewContainer(
		ctx,
		id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(snap, img),
		containerd.WithRuntime(m.runtimeProfile.RuntimeType, nil),
		containerd.WithNewSpec(specOpts...),
	)
	if err != nil {
		return model.ContainerState{}, err
	}

	task, err := ctr.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return model.ContainerState{}, err
	}

	if err := task.Start(ctx); err != nil {
		return model.ContainerState{}, err
	}

	return model.ContainerState{
		ID:          id,
		Name:        name,
		Image:       normalizeImage(image),
		Args:        args,
		Env:         env,
		SnapshotKey: snap,
		TaskPID:     task.Pid(),
		Runtime:     m.runtimeProfile.RuntimeType,
		TaskStatus:  "running",
	}, nil
}

func containerResolvConfPath() string {
	const upstream = "/run/systemd/resolve/resolv.conf"
	if st, err := os.Stat(upstream); err == nil && !st.IsDir() {
		return upstream
	}

	const fallback = "/etc/resolv.conf"
	if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
		return fallback
	}

	return ""
}

func (m *Manager) stopAndDeleteContainer(ctx context.Context, id, snapshotKey string) error {
	ctr, err := m.client.LoadContainer(ctx, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}

		return err
	}

	task, err := ctr.Task(ctx, nil)
	if err == nil {
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}

	if err := ctr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil && !strings.Contains(err.Error(), "not found") {
		return err
	}

	_ = snapshotKey
	return nil
}

func (m *Manager) isSandboxHealthy(ctx context.Context, sbx *model.Sandbox) bool {
	ctr, err := m.client.LoadContainer(ctx, sbx.Pause.ID)
	if err != nil {
		return false
	}

	task, err := ctr.Task(ctx, nil)
	if err != nil {
		return false
	}

	status, err := task.Status(ctx)
	if err != nil {
		return false
	}

	return string(status.Status) == "running"
}

func (m *Manager) deleteSandboxFromState(ctx context.Context, sbx *model.Sandbox) error {
	var errs []error
	for _, name := range sortedContainerNames(sbx.Containers) {
		if e := m.stopAndDeleteContainer(ctx, sbx.Containers[name].ID, sbx.Containers[name].SnapshotKey); e != nil {
			errs = append(errs, e)
		}
	}

	_ = network.DelSandboxNetwork(ctx, m.cni, m.netConf, sbx.ID, sbx.NetNSPath, toCNIPorts(sbx.Ports))
	network.DeleteSandboxRules(m.ipt, sbx.ID, sbx.IP, sbx.BridgeName, toPublishedPorts(sbx.Ports))

	_ = m.stopAndDeleteContainer(ctx, sbx.Pause.ID, sbx.Pause.SnapshotKey)
	_ = network.UnmountNetNS(sbx.NetNSPath)
	_ = m.store.Delete(sbx.ID)

	return errors.Join(errs...)
}

func withDefaultLimits(in model.ResourceLimits) model.ResourceLimits {
	if in.MemoryBytes == 0 {
		in.MemoryBytes = 128 * 1024 * 1024
	}

	if in.PidsLimit == 0 {
		in.PidsLimit = 128
	}

	if in.CPUPeriod == 0 {
		in.CPUPeriod = 100000
	}

	if in.CPUQuota == 0 {
		in.CPUQuota = 50000
	}

	return in
}

func normalizeImage(image string) string {
	if strings.Contains(image, "/") {
		return image
	}

	return "docker.io/library/" + image
}

func toCNIPorts(in []model.PortMapping) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, p := range in {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		out = append(out, map[string]any{"hostPort": p.HostPort, "containerPort": p.ContainerPort, "protocol": proto})
	}

	return out
}

func toPublishedPorts(in []model.PortMapping) []network.PublishedPort {
	out := make([]network.PublishedPort, 0, len(in))
	for _, p := range in {
		out = append(out, network.PublishedPort{
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	return out
}

func csvEnv(key string, def []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), def...)
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.ToUpper(strings.TrimSpace(p))
		if v == "" {
			continue
		}

		out = append(out, v)
	}

	if len(out) == 0 {
		return append([]string(nil), def...)
	}

	return out
}

func sortedContainerNames(m map[string]model.ContainerState) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}

	sort.Strings(k)
	return k
}

func (m *Manager) refreshSandboxRuntimeState(ctx context.Context, sbx *model.Sandbox) {
	sbx.Pause = m.fillContainerRuntimeState(ctx, sbx.Pause)
	for name, st := range sbx.Containers {
		sbx.Containers[name] = m.fillContainerRuntimeState(ctx, st)
	}
}

func (m *Manager) fillContainerRuntimeState(ctx context.Context, st model.ContainerState) model.ContainerState {
	ctr, err := m.client.LoadContainer(ctx, st.ID)
	if err != nil {
		st.TaskStatus = "not_found"
		return st
	}

	task, err := ctr.Task(ctx, nil)
	if err != nil {
		st.TaskStatus = "stopped"
		return st
	}

	status, err := task.Status(ctx)
	if err != nil {
		st.TaskStatus = "unknown"
		return st
	}

	st.TaskStatus = string(status.Status)
	st.ExitStatus = status.ExitStatus
	if !status.ExitTime.IsZero() {
		st.ExitTime = status.ExitTime.UTC().Format(time.RFC3339)
	}

	st.TaskPID = task.Pid()
	return st
}
