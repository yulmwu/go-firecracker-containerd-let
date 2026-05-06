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
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

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
	sbx := s.newSandboxState(req)
	created := false
	defer func() {
		if created {
			return
		}
		sbx.Phase = SandboxPhaseError
		sbx.UpdatedAt = time.Now().UTC()
		_ = s.deleteSandboxFromState(ctx, sbx)
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
	sbx.Phase = SandboxPhaseRunning
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

	sbx.Phase = SandboxPhaseDeleting
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

func normalizeProto(proto string) string {
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "" {
		return "tcp"
	}

	return p
}
