package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func (m *Manager) CreateSandbox(ctx context.Context, req model.CreateSandboxRequest) (*model.Sandbox, error) {
	unlock, err := m.acquireSandboxLock(req.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	unlockPorts, err := m.acquireSandboxLock("_ports")
	if err != nil {
		return nil, err
	}
	defer unlockPorts()

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if _, err := m.store.Load(req.ID); err == nil {
		return nil, fmt.Errorf("sandbox already exists: %s", req.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := m.ensureHostPortsAvailable(req.ID, req.Ports); err != nil {
		return nil, err
	}

	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	sbx := &model.Sandbox{ID: req.ID, Namespace: DefaultNS, Egress: req.Egress, BridgeName: m.bridgeIF, SubnetCIDR: m.cidr, CNIConfPath: "/etc/cni/net.d/10-sandbox-demo.conflist", Containers: map[string]model.ContainerState{}, CreatedAt: time.Now().UTC()}
	sbx.Ports = append(sbx.Ports, req.Ports...)
	created := false
	defer func() {
		if created {
			return
		}
		_ = m.deleteSandboxFromState(ctx, sbx)
	}()

	pause, err := m.createContainer(ctx, sbx.ID+"-pause", "pause", PauseImage, []string{}, nil, "", model.ResourceLimits{MemoryBytes: 64 * 1024 * 1024, CPUPeriod: 100000, CPUQuota: 30000, PidsLimit: 64}, "")
	if err != nil {
		return nil, err
	}
	sbx.Pause = pause

	netnsPath, err := network.BindMountNetNS(sbx.Pause.TaskPID, sbx.ID)
	if err != nil {
		return nil, err
	}
	sbx.NetNSPath = netnsPath

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

	if err := m.waitSandboxReady(ctx, sbx); err != nil {
		return nil, err
	}

	m.refreshSandboxRuntimeState(ctx, sbx)
	if err := m.store.Save(sbx); err != nil {
		return nil, err
	}

	created = true
	return sbx, nil
}

func (m *Manager) DeleteSandbox(ctx context.Context, sandboxID string) error {
	unlock, err := m.acquireSandboxLock(sandboxID)
	if err != nil {
		return err
	}
	defer unlock()

	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	sbx, err := m.store.Load(sandboxID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	var errs []error
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

func (m *Manager) ensureHostPortsAvailable(sandboxID string, requested []model.PortMapping) error {
	if len(requested) == 0 {
		return nil
	}

	type owner struct {
		sandboxID string
		proto     string
	}

	used := map[int]owner{}
	all, err := m.store.List()
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

func (m *Manager) waitSandboxReady(ctx context.Context, sbx *model.Sandbox) error {
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		allRunning := true
		for _, c := range sbx.Containers {
			ctr, err := m.client.LoadContainer(ctx, c.ID)
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

		if allRunning && m.publishedPortsReady(sbx) {
			return nil
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("sandbox not ready: %s", sbx.ID)
}

func (m *Manager) publishedPortsReady(sbx *model.Sandbox) bool {
	for _, p := range sbx.Ports {
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		if proto == "" {
			proto = "tcp"
		}

		if proto != "tcp" {
			continue
		}

		addr := fmt.Sprintf("%s:%d", sbx.IP, p.ContainerPort)
		conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
		if err != nil {
			return false
		}

		_ = conn.Close()
	}

	return true
}
