package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func (s *Service) CreateSandbox(ctx context.Context, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	return s.createSandbox(ctx, req, false)
}

func (s *Service) CreateSandboxAsync(ctx context.Context, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	sbx, err := s.createSandbox(ctx, req, true)
	if err != nil {
		return nil, err
	}

	return sbx, nil
}

func (s *Service) createSandbox(ctx context.Context, req model.CreateSandboxRequest, async bool) (*model.Sandbox, error) {
	opCtx, opCancel := context.WithTimeout(ctx, 90*time.Second)
	defer opCancel()
	ctx = opCtx

	unlock, err := s.acquireSandboxLock(req.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if _, err := s.store.Load(req.ID); err == nil {
		return nil, fmt.Errorf("sandbox already exists: %s", req.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ctx = namespaces.WithNamespace(ctx, s.namespace)
	if s.hasRuntimeArtifacts(req.ID) {
		_ = s.cleanupOrphanRuntimeSandbox(ctx, req.ID)
		_ = s.cleanupShimArtifacts(req.ID)
		_ = s.cleanupCNICache(req.ID)
	}

	unlockPorts, err := s.acquireSandboxLock("_ports")
	if err != nil {
		return nil, err
	}

	if err := s.ensureHostPortsAvailable(req.ID, req.Ports); err != nil {
		unlockPorts()
		return nil, err
	}
	releasePorts := s.reserveRequestedPorts(req.ID, req.Ports)
	unlockPorts()
	defer releasePorts()

	sbx := s.newSandboxState(req)
	if err := s.store.Save(sbx); err != nil {
		return nil, err
	}

	if async {
		// Provision in background; caller can poll via GET/LIST.
		go s.provisionSandbox(req.ID, req)
		return sbx, nil
	}

	return s.provisionSandboxSync(ctx, sbx, req)
}

func (s *Service) provisionSandbox(sandboxID string, req model.CreateSandboxRequest) {
	bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bgCtx = namespaces.WithNamespace(bgCtx, s.namespace)

	unlock, err := s.acquireSandboxLock(sandboxID)
	if err != nil {
		s.markSandboxError(sandboxID, err)
		return
	}
	defer unlock()

	sbx, err := s.store.Load(sandboxID)
	if err != nil {
		return
	}

	if _, err := s.provisionSandboxSync(bgCtx, sbx, req); err != nil {
		s.markSandboxError(sandboxID, err)
	}
}

func (s *Service) provisionSandboxSync(ctx context.Context, sbx *model.Sandbox, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	ctx = namespaces.WithNamespace(ctx, s.namespace)
	created := false
	defer func() {
		if created {
			return
		}
		setSandboxPhase(sbx, SandboxPhaseError, sbx.Error)
		if sbx.Error == "" {
			sbx.Error = "provision failed"
		}
		_ = s.store.Save(sbx)
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = s.deleteSandboxRuntimeArtifacts(namespaces.WithNamespace(cctx, s.namespace), sbx)
	}()

	vmCtx, vmCancel := context.WithTimeout(ctx, 40*time.Second)
	defer vmCancel()
	if err := s.createVM(vmCtx, sbx.ID, len(req.Containers)); err != nil {
		return nil, err
	}

	for _, c := range req.Containers {
		ctrCtx, ctrCancel := context.WithTimeout(ctx, 25*time.Second)
		st, err := s.createContainer(ctrCtx, sbx.ID+"-"+c.Name, c.Name, c.Image, c.Args, c.Env, c.WorkDir, withDefaultLimits(c.Limits), sbx.ID)
		ctrCancel()
		if err != nil {
			sbx.Error = err.Error()
			return nil, err
		}

		sbx.Containers[c.Name] = st
	}

	ipCtx, ipCancel := context.WithTimeout(ctx, 15*time.Second)
	defer ipCancel()
	ip, err := s.resolveSandboxIP(ipCtx, sbx.ID)
	if err != nil {
		return nil, err
	}

	sbx.IP = ip
	if err := s.applySandboxNetworkPolicy(sbx); err != nil {
		return nil, err
	}

	readyCtx, readyCancel := context.WithTimeout(ctx, 18*time.Second)
	defer readyCancel()
	if err := s.waitSandboxReady(readyCtx, sbx); err != nil {
		return nil, err
	}
	if err := s.applyHostPortPublish(sbx); err != nil {
		return nil, err
	}
	// Published TCP readiness is best-effort; runtime task readiness is the
	// primary success signal. Some images open ports slightly after task start.
	_ = s.waitPublishedTCPReady(sbx)

	s.refreshSandboxRuntimeState(ctx, sbx)
	setSandboxPhase(sbx, SandboxPhaseRunning, "")
	if err := s.store.Save(sbx); err != nil {
		return nil, err
	}

	created = true
	return sbx, nil
}

func (s *Service) markSandboxError(sandboxID string, err error) {
	sbx, loadErr := s.store.Load(sandboxID)
	if loadErr != nil {
		return
	}

	msg := ""
	if err != nil {
		msg = err.Error()
	}

	setSandboxPhase(sbx, SandboxPhaseError, msg)
	_ = s.store.Save(sbx)
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
			s.releaseReservedPorts(sandboxID)
			return nil
		}

		return err
	}

	setSandboxPhase(sbx, SandboxPhaseDeleting, "")

	_ = s.store.Save(sbx)
	err = s.deleteSandboxFromState(ctx, sbx)
	s.releaseReservedPorts(sandboxID)
	s.clearUnhealthy(sandboxID)

	return err
}

func (s *Service) ListSandboxes(_ context.Context) ([]*model.Sandbox, error) {
	ctx := namespaces.WithNamespace(context.Background(), s.namespace)
	all, err := s.store.List()
	if err != nil {
		return nil, err
	}

	out := make([]*model.Sandbox, 0, len(all))
	for _, sbx := range all {
		cp := copySandbox(sbx)
		s.refreshSandboxRuntimeState(ctx, cp)
		out = append(out, cp)
	}

	return out, nil
}

func (s *Service) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	sbx, err := s.store.Load(id)
	if err != nil {
		return nil, err
	}

	cp := copySandbox(sbx)
	s.refreshSandboxRuntimeState(namespaces.WithNamespace(ctx, s.namespace), cp)
	return cp, nil
}

func (s *Service) ensureHostPortsAvailable(sandboxID string, requested []model.PortMapping) error {
	if len(requested) == 0 {
		return nil
	}

	used := map[int]struct {
		sandboxID string
		proto     string
	}{}
	all, err := s.store.List()
	if err != nil {
		return err
	}

	for _, sb := range all {
		if sb.ID == sandboxID {
			continue
		}

		for _, p := range sb.Ports {
			proto := normalizeProto(p.Protocol)
			used[p.HostPort] = struct {
				sandboxID string
				proto     string
			}{sandboxID: sb.ID, proto: proto}
		}
	}

	for _, p := range requested {
		proto := normalizeProto(p.Protocol)
		if o, ok := used[p.HostPort]; ok && o.proto == proto {
			return fmt.Errorf("host port already in use: %d/%s (sandbox %s)", p.HostPort, proto, o.sandboxID)
		}

		if owner, ok := s.reservedPortOwner(p.HostPort, proto); ok && owner != sandboxID {
			return fmt.Errorf("host port already reserved: %d/%s (sandbox %s)", p.HostPort, proto, owner)
		}

		if err := ensureLocalPortFree(p.HostPort, proto); err != nil {
			return fmt.Errorf("host port already in use: %d/%s (%v)", p.HostPort, proto, err)
		}
	}

	return nil
}

func (s *Service) reserveRequestedPorts(sandboxID string, requested []model.PortMapping) func() {
	keys := make([]string, 0, len(requested))
	s.portMu.Lock()
	for _, p := range requested {
		k := portKey(p.HostPort, normalizeProto(p.Protocol))
		s.reservedPorts[k] = sandboxID
		keys = append(keys, k)
	}
	s.portMu.Unlock()

	return func() {
		s.portMu.Lock()
		for _, k := range keys {
			if s.reservedPorts[k] == sandboxID {
				delete(s.reservedPorts, k)
			}
		}

		s.portMu.Unlock()
	}
}

func (s *Service) releaseReservedPorts(sandboxID string) {
	s.portMu.Lock()
	for k, v := range s.reservedPorts {
		if v == sandboxID {
			delete(s.reservedPorts, k)
		}
	}

	s.portMu.Unlock()
}

func (s *Service) reservedPortOwner(port int, proto string) (string, bool) {
	s.portMu.Lock()
	defer s.portMu.Unlock()
	v, ok := s.reservedPorts[portKey(port, proto)]

	return v, ok
}

func portKey(port int, proto string) string {
	return fmt.Sprintf("%d/%s", port, normalizeProto(proto))
}

func ensureLocalPortFree(port int, proto string) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	if proto == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		_ = pc.Close()

		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	_ = ln.Close()
	return nil
}

func (s *Service) waitSandboxReady(ctx context.Context, sbx *model.Sandbox) error {
	deadline := time.Now().Add(DefaultReadyTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("sandbox %s readiness canceled: %w", sbx.ID, ctx.Err())
		default:
		}
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

func normalizeProto(proto string) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "" {
		return "tcp"
	}

	return p
}

func (s *Service) waitPublishedTCPReady(sbx *model.Sandbox) error {
	deadline := time.Now().Add(10 * time.Second)
	consecutive := 0
	for time.Now().Before(deadline) {
		allReady := true
		for _, p := range sbx.Ports {
			if normalizeProto(p.Protocol) != "tcp" {
				continue
			}

			addr := net.JoinHostPort(sbx.IP, fmt.Sprintf("%d", p.ContainerPort))
			conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
			if err != nil {
				allReady = false
				break
			}

			_ = conn.Close()
		}

		if allReady {
			consecutive++
			if consecutive >= 4 {
				return nil
			}
		} else {
			consecutive = 0
		}

		time.Sleep(150 * time.Millisecond)
	}

	return fmt.Errorf("sandbox %s tcp ports not ready before timeout", sbx.ID)
}

func (s *Service) hasRuntimeArtifacts(sandboxID string) bool {
	if sandboxID == "" {
		return false
	}

	if _, err := os.Stat(filepath.Join("/var/lib/cni", sandboxID)); err == nil {
		return true
	}

	if _, err := os.Stat(filepath.Join("/var/lib/firecracker-containerd/shim-base", s.namespace+"#"+sandboxID)); err == nil {
		return true
	}

	ctx := namespaces.WithNamespace(context.Background(), s.namespace)
	containers, err := s.client.Containers(ctx)
	if err != nil {
		return false
	}

	for _, c := range containers {
		if strings.HasPrefix(c.ID(), sandboxID+"-") {
			return true
		}
	}

	return false
}

func copySandbox(in *model.Sandbox) *model.Sandbox {
	if in == nil {
		return nil
	}

	out := *in
	out.Ports = append([]model.PortMapping(nil), in.Ports...)
	out.Containers = make(map[string]model.ContainerState, len(in.Containers))
	for k, v := range in.Containers {
		cp := v
		cp.Args = append([]string(nil), v.Args...)
		cp.Env = append([]string(nil), v.Env...)
		out.Containers[k] = cp
	}

	return &out
}
