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
	s.dbg("vm create call vm=%s container_count=%d", vmID, containerCount)
	c, err := fcclient.New(s.containerdAddr + ".ttrpc")
	if err != nil {
		return err
	}

	defer c.Close()

	if containerCount < 1 {
		containerCount = 1
	}

	for attempt := 1; attempt <= 4; attempt++ {
		s.dbg("vm create attempt vm=%s attempt=%d", vmID, attempt)
		_, err = c.CreateVM(ctx, &proto.CreateVMRequest{VMID: vmID, ContainerCount: int32(containerCount), NetworkInterfaces: []*proto.FirecrackerNetworkInterface{{CNIConfig: &proto.CNIConfiguration{NetworkName: "fcnet", InterfaceName: "veth0", ConfDir: "/etc/cni/net.d", BinPath: []string{"/opt/cni/bin"}}}}})
		if err == nil {
			s.dbg("vm create success vm=%s", vmID)
			return nil
		}
		s.dbg("vm create error vm=%s attempt=%d err=%v", vmID, attempt, err)

		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already exists") {
			return nil
		}

		if !strings.Contains(msg, "vsock") && !strings.Contains(msg, "dial unix firecracker.vsock") {
			return fmt.Errorf("create vm %s: %w", vmID, err)
		}

		// Best-effort cleanup before retry to avoid stale half-created VM state.
		_, _ = c.StopVM(ctx, &proto.StopVMRequest{VMID: vmID})
		time.Sleep(time.Duration(150*attempt) * time.Millisecond)
	}

	return fmt.Errorf("create vm %s: %w", vmID, err)
}

func (s *Service) stopVM(ctx context.Context, vmID string) error {
	s.dbg("vm stop call vm=%s", vmID)
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
	s.dbg("container create call id=%s vm=%s image=%s", id, vmID, image)
	ref := normalizeImage(image)
	baseSpecOpts := []oci.SpecOpts{
		oci.WithNoNewPrivileges,
		seccomp.WithDefaultProfile(),
		oci.WithHostHostsFile,
		oci.WithHostResolvconf,
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
		s.dbg("container create snapshotter id=%s snapshotter=%s", id, snapshotter)
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
		for attempt := 1; attempt <= 4; attempt++ {
			s.dbg("container create attempt id=%s snapshotter=%s attempt=%d", id, snapshotter, attempt)
			_ = os.MkdirAll(filepath.Join("/run/firecracker-containerd/io.containerd.runtime.v2.task", s.namespace), 0o755)
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
					break
				}

				return model.ContainerState{}, fmt.Errorf("new container %q: %w", id, err)
			}

			task, err := ctr.NewTask(ctx, cio.NewCreator(cio.WithStdio))
			if err != nil {
				_ = ctr.Delete(ctx)
				if isTransientRuntimeErr(err) {
					time.Sleep(time.Duration(120*attempt) * time.Millisecond)
					continue
				}

				return model.ContainerState{}, fmt.Errorf("new task %q: %w", id, err)
			}

			if err := task.Start(ctx); err != nil {
				_, _ = task.Delete(ctx, containerd.WithProcessKill)
				_ = ctr.Delete(ctx)
				if isTransientRuntimeErr(err) {
					time.Sleep(time.Duration(120*attempt) * time.Millisecond)
					continue
				}

				return model.ContainerState{}, fmt.Errorf("start task %q: %w", id, err)
			}
			s.dbg("container create success id=%s pid=%d", id, task.Pid())

			return model.ContainerState{ID: id, Name: name, Phase: ContainerPhaseRunning, Image: ref, Args: args, Env: env, SnapshotKey: snap, TaskPID: task.Pid(), Runtime: "aws.firecracker", TaskStatus: "running"}, nil
		}
	}

	if lastErr != nil {
		return model.ContainerState{}, fmt.Errorf("no usable snapshotter for %q: %w", ref, lastErr)
	}

	return model.ContainerState{}, fmt.Errorf("no usable snapshotter for %q", ref)
}

func isTransientRuntimeErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "vsock") ||
		strings.Contains(msg, "cannot start a container that has stopped") ||
		strings.Contains(msg, "failed to dial") ||
		strings.Contains(msg, "connection refused")
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

		// Firecracker/containerd can fail snapshot cleanup when snapshotter plugin
		// is transiently unhealthy; keep-snapshot still removes container metadata.
		if derr := ctr.Delete(ctx); derr == nil || strings.Contains(strings.ToLower(derr.Error()), "not found") {
			return nil
		}
		return err
	}

	return nil
}

func (s *Service) deleteSandboxFromState(ctx context.Context, sbx *model.Sandbox) error {
	err := s.deleteSandboxRuntimeArtifacts(ctx, sbx)
	_ = s.store.Delete(sbx.ID)
	return err
}

func (s *Service) deleteSandboxRuntimeArtifacts(ctx context.Context, sbx *model.Sandbox) error {
	s.dbg("cleanup runtime artifacts sandbox=%s", sbx.ID)
	var errs []error
	for _, name := range sortedContainerNames(sbx.Containers) {
		if e := s.stopAndDeleteContainer(ctx, sbx.Containers[name].ID); e != nil {
			errs = append(errs, e)
		}
	}

	s.cleanupHostPortPublish(sbx)
	s.cleanupSandboxNetworkPolicy(sbx)
	_ = s.cleanupShimArtifacts(sbx.ID)
	_ = s.cleanupCNICache(sbx.ID)
	_ = s.stopVM(ctx, sbx.ID)
	s.dbg("cleanup runtime artifacts done sandbox=%s err_count=%d", sbx.ID, len(errs))

	return errors.Join(errs...)
}

func (s *Service) cleanupShimArtifacts(sandboxID string) error {
	_ = os.RemoveAll(filepath.Join("/var/lib/firecracker-containerd/shim-base", s.namespace+"#"+sandboxID))
	base := filepath.Join("/run/firecracker-containerd/io.containerd.runtime.v2.task", s.namespace)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if strings.HasPrefix(e.Name(), sandboxID+"-") {
			_ = os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}

	return nil
}

func (s *Service) cleanupCNICache(sandboxID string) error {
	if sandboxID == "" {
		return nil
	}

	_ = os.RemoveAll(filepath.Join("/var/lib/cni", sandboxID))

	return nil
}

func (s *Service) resolveSandboxIP(ctx context.Context, sandboxID string) (string, error) {
	deadline := time.Now().Add(12 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("resolve sandbox ip canceled: %w", ctx.Err())
		default:
		}
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
	s.dbg("apply sandbox firewall sandbox=%s ip=%s", sbx.ID, sbx.IP)
	return network.ApplySandboxRules(s.ipt, sbx.ID, sbx.IP, s.cidr, s.bridgeIF, sbx.Egress, toPublishedPorts(sbx.Ports))
}

func (s *Service) applyHostPortPublish(sbx *model.Sandbox) error {
	s.dbg("apply hostport dnat sandbox=%s ip=%s ports=%v", sbx.ID, sbx.IP, sbx.Ports)
	return network.ApplyHostPortDNAT(s.ipt, sbx.ID, sbx.IP, toHostPortForwards(sbx.Ports))
}

func (s *Service) cleanupHostPortPublish(sbx *model.Sandbox) {
	s.dbg("cleanup hostport dnat sandbox=%s ip=%s ports=%v", sbx.ID, sbx.IP, sbx.Ports)
	if sbx.IP != "" {
		network.DeleteHostPortDNAT(s.ipt, sbx.ID, sbx.IP, toHostPortForwards(sbx.Ports))
	}

	// Fallback cleanup by tagged rules handles partial-failure/orphan cases
	// where state/port metadata is incomplete.
	network.DeleteHostPortDNATBySandbox(s.ipt, sbx.ID)
}

func (s *Service) cleanupSandboxNetworkPolicy(sbx *model.Sandbox) {
	if sbx.IP == "" {
		return
	}

	network.DeleteSandboxRules(s.ipt, sbx.ID, sbx.IP, sbx.BridgeName, toPublishedPorts(sbx.Ports))
}

func (s *Service) refreshSandboxRuntimeState(ctx context.Context, sbx *model.Sandbox) {
	if sbx.Phase == SandboxPhaseError && sbx.Error != "" {
		// Preserve terminal provisioning errors captured in state.
		sbx.UpdatedAt = time.Now().UTC()
		return
	}

	if len(sbx.Containers) == 0 {
		// Keep explicit lifecycle phase when container plan is absent.
		// This prevents empty-state sandboxes from being misreported as running.
		sbx.UpdatedAt = time.Now().UTC()
		return
	}

	hasError := false
	sandboxErr := ""
	allRunning := true
	inCreateGrace := sbx.Phase == SandboxPhaseCreating && time.Since(sbx.CreatedAt) < DefaultReadyTimeout

	for name, st := range sbx.Containers {
		next := s.fillContainerRuntimeState(ctx, st)
		if inCreateGrace && next.TaskStatus == "not_found" {
			next.Phase = ContainerPhaseCreating
			next.Error = ""
			next.TaskStatus = "creating"
		}

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
	case sbx.Phase == SandboxPhaseDeleting:
		// keep explicit deleting state during delete flow
	case hasError:
		sbx.Phase = SandboxPhaseError
		sbx.Error = sandboxErr
	case allRunning:
		sbx.Phase = SandboxPhaseRunning
		sbx.Error = ""
	default:
		sbx.Phase = SandboxPhaseCreating
	}

	sbx.UpdatedAt = time.Now().UTC()
}

func (s *Service) fillContainerRuntimeState(ctx context.Context, st model.ContainerState) model.ContainerState {
	ctr, err := s.client.LoadContainer(ctx, st.ID)
	if err != nil {
		st.TaskStatus = "not_found"
		st.Phase = ContainerPhaseError
		st.Error = "container not found"

		return st
	}

	task, err := ctr.Task(ctx, nil)
	if err != nil {
		st.TaskStatus = "stopped"
		st.Phase = ContainerPhaseStopped
		st.Error = ""
		return st
	}

	status, err := task.Status(ctx)
	if err != nil {
		st.TaskStatus = "unknown"
		st.Phase = ContainerPhaseError
		st.Error = "failed to read task status"
		return st
	}

	st.TaskStatus = string(status.Status)
	st.Error = ""
	st.Phase = taskStatusToContainerPhase(st.TaskStatus)

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

func taskStatusToContainerPhase(taskStatus string) string {
	switch taskStatus {
	case "running":
		return ContainerPhaseRunning
	case "created":
		return ContainerPhaseCreating
	case "stopped", "paused", "pausing":
		return ContainerPhaseStopped
	default:
		return ContainerPhaseUnknown
	}
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

func toHostPortForwards(in []model.PortMapping) []network.HostPortForward {
	out := make([]network.HostPortForward, 0, len(in))
	for _, p := range in {
		out = append(out, network.HostPortForward{
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	return out
}

func (s *Service) acquireSandboxLock(id string) (func(), error) {
	lockPath := filepath.Join(s.lockDir, id+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(DefaultLockWaitTimeout)
	for {
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		} else if err != unix.EWOULDBLOCK {
			_ = f.Close()
			return nil, err
		}

		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("lock timeout: %s", id)
		}

		time.Sleep(120 * time.Millisecond)
	}

	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

func (s *Service) isSandboxLockHeld(id string) bool {
	lockPath := filepath.Join(s.lockDir, id+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err == unix.EWOULDBLOCK
	}

	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)

	return false
}
