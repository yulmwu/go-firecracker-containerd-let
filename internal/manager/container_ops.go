package manager

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

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

	return model.ContainerState{ID: id, Name: name, Image: normalizeImage(image), Args: args, Env: env, SnapshotKey: snap, TaskPID: task.Pid(), Runtime: m.runtimeProfile.RuntimeType, TaskStatus: "running"}, nil
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

func sortedContainerNames(m map[string]model.ContainerState) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}

	sort.Strings(k)
	return k
}
