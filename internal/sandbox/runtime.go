package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	containerd "github.com/containerd/containerd/v2/client"
	seccomp "github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	fcclient "github.com/firecracker-microvm/firecracker-containerd/firecracker-control/client"
	"github.com/firecracker-microvm/firecracker-containerd/proto"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func (s *Service) createVM(ctx context.Context, vmID string, containerCount int) error {
	c, err := fcclient.New(s.containerdAddr + ".ttrpc")
	if err != nil {
		return err
	}

	defer c.Close()

	if containerCount < 1 {
		containerCount = 1
	}

	_, err = c.CreateVM(ctx, &proto.CreateVMRequest{VMID: vmID, ContainerCount: int32(containerCount), NetworkInterfaces: []*proto.FirecrackerNetworkInterface{{CNIConfig: &proto.CNIConfiguration{NetworkName: "fcnet", InterfaceName: "veth0", ConfDir: "/etc/cni/net.d", BinPath: []string{"/opt/cni/bin"}}}}})
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "already exists") {
		return nil
	}

	if err != nil {
		return fmt.Errorf("create vm %s: %w", vmID, err)
	}

	return nil
}

func (s *Service) stopVM(ctx context.Context, vmID string) error {
	c, err := fcclient.New(s.containerdAddr + ".ttrpc")
	if err != nil {
		return err
	}

	defer c.Close()

	_, err = c.StopVM(ctx, &proto.StopVMRequest{VMID: vmID})
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "forcefully terminated") {
			return nil
		}
		return fmt.Errorf("stop vm %s: %w", vmID, err)
	}

	return nil
}

func (s *Service) createContainer(ctx context.Context, id, name, image string, args, env []string, workDir string, lim model.ResourceLimits, vmID string) (model.ContainerState, error) {
	ref := normalizeImage(image)
	baseSpecOpts := []oci.SpecOpts{
		oci.WithNoNewPrivileges,
		seccomp.WithDefaultProfile(),
		oci.WithMaskedPaths([]string{"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"}),
		oci.WithReadonlyPaths([]string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}),
		oci.WithMemoryLimit(uint64(lim.MemoryBytes)),
		oci.WithPidsLimit(lim.PidsLimit),
		oci.WithCPUCFS(lim.CPUQuota, lim.CPUPeriod),
		oci.WithAnnotations(map[string]string{"aws.firecracker.vm.id": vmID}),
		oci.WithHostNamespace(specs.NetworkNamespace),
	}

	if len(args) > 0 {
		baseSpecOpts = append(baseSpecOpts, oci.WithProcessArgs(args...))
	}

	if len(env) > 0 {
		baseSpecOpts = append(baseSpecOpts, oci.WithEnv(env))
	}

	if workDir != "" {
		baseSpecOpts = append(baseSpecOpts, oci.WithProcessCwd(workDir))
	}

	var lastErr error
	for _, snapshotter := range s.snapshotterCandidates() {
		img, err := s.client.GetImage(ctx, ref)
		if err != nil {
			img, err = s.client.Pull(ctx, ref, containerd.WithPullSnapshotter(snapshotter))
			if err != nil {
				if isSnapshotterErr(err) {
					lastErr = err
					continue
				}

				return model.ContainerState{}, fmt.Errorf("pull image %q: %w", ref, err)
			}
		}

		if err := img.Unpack(ctx, snapshotter); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") {
			if isSnapshotterErr(err) {
				lastErr = err
				continue
			}

			return model.ContainerState{}, fmt.Errorf("unpack image %q with snapshotter %q: %w", ref, snapshotter, err)
		}

		specOpts := append([]oci.SpecOpts{oci.WithImageConfig(img)}, baseSpecOpts...)

		snap := id + "-snapshot"
		ctr, err := s.client.NewContainer(ctx, id,
			containerd.WithImage(img),
			containerd.WithSnapshotter(snapshotter),
			containerd.WithNewSnapshot(snap, img),
			containerd.WithRuntime("aws.firecracker", nil),
			containerd.WithNewSpec(specOpts...),
		)

		if err != nil {
			if isSnapshotterErr(err) {
				lastErr = err
				continue
			}

			return model.ContainerState{}, fmt.Errorf("new container %q: %w", id, err)
		}

		task, err := ctr.NewTask(ctx, cio.NewCreator(cio.WithStdio))
		if err != nil {
			return model.ContainerState{}, fmt.Errorf("new task %q: %w", id, err)
		}

		if err := task.Start(ctx); err != nil {
			return model.ContainerState{}, fmt.Errorf("start task %q: %w", id, err)
		}

		return model.ContainerState{ID: id, Name: name, Phase: "running", Image: ref, Args: args, Env: env, SnapshotKey: snap, TaskPID: task.Pid(), Runtime: "aws.firecracker", TaskStatus: "running"}, nil
	}

	if lastErr != nil {
		return model.ContainerState{}, fmt.Errorf("no usable snapshotter for %q: %w", ref, lastErr)
	}

	return model.ContainerState{}, fmt.Errorf("no usable snapshotter for %q", ref)
}

func (s *Service) snapshotterCandidates() []string {
	if v := strings.TrimSpace(os.Getenv("SANDBOX_SNAPSHOTTER")); v != "" {
		return []string{v}
	}

	return []string{"devmapper", "overlayfs", "native"}
}

func isSnapshotterErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "snapshotter not loaded") || strings.Contains(msg, "invalid argument")
}

func (s *Service) stopAndDeleteContainer(ctx context.Context, id string) error {
	ctr, err := s.client.LoadContainer(ctx, id)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil
		}

		return err
	}

	if task, err := ctr.Task(ctx, nil); err == nil {
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}

	if err := ctr.Delete(ctx, containerd.WithSnapshotCleanup); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		if strings.Contains(strings.ToLower(err.Error()), "running task") || strings.Contains(strings.ToLower(err.Error()), "failed precondition") {
			if task, terr := ctr.Task(ctx, nil); terr == nil {
				_ = task.Kill(ctx, syscall.SIGKILL)
				_, _ = task.Delete(ctx, containerd.WithProcessKill)
			}

			if derr := ctr.Delete(ctx, containerd.WithSnapshotCleanup); derr != nil && !strings.Contains(strings.ToLower(derr.Error()), "not found") {
				return derr
			}

			return nil
		}

		return err
	}

	return nil
}

func (s *Service) deleteSandboxFromState(ctx context.Context, sbx *model.Sandbox) error {
	var errs []error
	for _, name := range sortedContainerNames(sbx.Containers) {
		if e := s.stopAndDeleteContainer(ctx, sbx.Containers[name].ID); e != nil {
			errs = append(errs, e)
		}
	}

	s.cleanupSandboxNetworkPolicy(sbx)
	_ = s.store.Delete(sbx.ID)
	_ = s.stopVM(ctx, sbx.ID)

	return errors.Join(errs...)
}

func (s *Service) resolveSandboxIP(_ context.Context, sandboxID string) (string, error) {
	deadline := time.Now().Add(12 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ip, err := network.LookupFCNetIPv4FromResultCache(sandboxID)
		if err == nil {
			return ip, nil
		}

		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("timeout resolving sandbox ip")
	}

	return "", lastErr
}

func (s *Service) applySandboxNetworkPolicy(sbx *model.Sandbox) error {
	return network.ApplySandboxRules(s.ipt, sbx.ID, sbx.IP, s.cidr, s.bridgeIF, sbx.Egress, toPublishedPorts(sbx.Ports))
}

func (s *Service) cleanupSandboxNetworkPolicy(sbx *model.Sandbox) {
	if sbx.IP == "" {
		return
	}

	pub, hostPorts := toHostPortRules(sbx.Ports)
	network.DeleteSandboxRules(s.ipt, sbx.ID, sbx.IP, sbx.BridgeName, pub)
	if len(hostPorts) > 0 {
		network.DeleteHostPortDNAT(s.ipt, sbx.IP, pub, hostPorts)
	}
}

func (s *Service) refreshSandboxRuntimeState(ctx context.Context, sbx *model.Sandbox) {
	hasError := false
	sandboxErr := ""
	allRunning := true

	for name, st := range sbx.Containers {
		next := s.fillContainerRuntimeState(ctx, st)
		sbx.Containers[name] = next
		if next.Phase == "error" {
			hasError = true
			if sandboxErr == "" && next.Error != "" {
				sandboxErr = next.Error
			}
		}

		if next.Phase != "running" {
			allRunning = false
		}
	}

	switch {
	case sbx.Phase == "deleting":
		// keep explicit deleting state during delete flow
	case hasError:
		sbx.Phase = "error"
		sbx.Error = sandboxErr
	case allRunning:
		sbx.Phase = "running"
		sbx.Error = ""
	default:
		sbx.Phase = "creating"
	}

	sbx.UpdatedAt = time.Now().UTC()
}

func (s *Service) fillContainerRuntimeState(ctx context.Context, st model.ContainerState) model.ContainerState {
	ctr, err := s.client.LoadContainer(ctx, st.ID)
	if err != nil {
		st.TaskStatus = "not_found"
		st.Phase = "error"
		st.Error = "container not found"

		return st
	}

	task, err := ctr.Task(ctx, nil)
	if err != nil {
		st.TaskStatus = "stopped"
		st.Phase = "stopped"
		st.Error = ""
		return st
	}

	status, err := task.Status(ctx)
	if err != nil {
		st.TaskStatus = "unknown"
		st.Phase = "error"
		st.Error = "failed to read task status"
		return st
	}

	st.TaskStatus = string(status.Status)
	st.Error = ""
	switch st.TaskStatus {
	case "running":
		st.Phase = "running"
	case "created":
		st.Phase = "creating"
	case "stopped", "paused", "pausing":
		st.Phase = "stopped"
	default:
		st.Phase = "unknown"
	}

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

func toPublishedPorts(in []model.PortMapping) []network.PublishedPort {
	out := make([]network.PublishedPort, 0, len(in))
	for _, p := range in {
		out = append(out, network.PublishedPort{ContainerPort: p.ContainerPort, Protocol: p.Protocol})
	}

	return out
}

func toHostPortRules(in []model.PortMapping) ([]network.PublishedPort, []int) {
	pub := make([]network.PublishedPort, 0, len(in))
	hostPorts := make([]int, 0, len(in))
	for _, p := range in {
		pub = append(pub, network.PublishedPort{ContainerPort: p.ContainerPort, Protocol: p.Protocol})
		hostPorts = append(hostPorts, p.HostPort)
	}

	return pub, hostPorts
}

func (s *Service) acquireSandboxLock(id string) (func(), error) {
	lockPath := filepath.Join(s.lockDir, id+".lock")
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
