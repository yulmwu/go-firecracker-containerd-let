package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

func (m *Manager) Reconcile(ctx context.Context) error {
	ctx = namespaces.WithNamespace(ctx, DefaultNS)
	all, err := m.store.List()
	if err != nil {
		return err
	}

	var errs []error
	stateIDs := make(map[string]struct{}, len(all))
	for _, sbx := range all {
		stateIDs[sbx.ID] = struct{}{}
		unlock, lerr := m.acquireSandboxLock(sbx.ID)
		if lerr != nil {
			errs = append(errs, lerr)
			continue
		}

		if !m.isSandboxHealthy(ctx, sbx) {
			if e := m.deleteSandboxFromState(ctx, sbx); e != nil {
				errs = append(errs, fmt.Errorf("reconcile %s: %w", sbx.ID, e))
			}
		}

		unlock()
	}

	orphanIDs, oerr := m.findOrphanSandboxIDs(ctx, stateIDs)
	if oerr != nil {
		errs = append(errs, oerr)
	}

	for _, id := range orphanIDs {
		unlock, lerr := m.acquireSandboxLock(id)
		if lerr != nil {
			errs = append(errs, lerr)
			continue
		}

		if _, serr := m.store.Load(id); errors.Is(serr, os.ErrNotExist) {
			if e := m.cleanupOrphanSandbox(ctx, id); e != nil {
				errs = append(errs, fmt.Errorf("reconcile orphan %s: %w", id, e))
			}
		} else if serr != nil {
			errs = append(errs, fmt.Errorf("reconcile orphan %s state check: %w", id, serr))
		}

		unlock()
	}

	return errors.Join(errs...)
}

func (m *Manager) isSandboxHealthy(ctx context.Context, sbx *model.Sandbox) bool {
	if !m.isContainerRunning(ctx, sbx.Pause.ID) {
		return false
	}

	for _, st := range sbx.Containers {
		if !m.isContainerRunning(ctx, st.ID) {
			return false
		}
	}

	return true
}

func (m *Manager) isContainerRunning(ctx context.Context, id string) bool {
	ctr, err := m.client.LoadContainer(ctx, id)
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

func (m *Manager) findOrphanSandboxIDs(ctx context.Context, stateIDs map[string]struct{}) ([]string, error) {
	containers, err := m.client.Containers(ctx)
	if err != nil {
		return nil, err
	}

	orphans := map[string]struct{}{}
	for _, c := range containers {
		id := c.ID()
		if !strings.HasSuffix(id, "-pause") {
			continue
		}

		sbxID := strings.TrimSuffix(id, "-pause")
		if sbxID == "" {
			continue
		}

		if _, ok := stateIDs[sbxID]; !ok {
			orphans[sbxID] = struct{}{}
		}
	}

	out := make([]string, 0, len(orphans))
	for id := range orphans {
		out = append(out, id)
	}

	sort.Strings(out)
	return out, nil
}

func (m *Manager) cleanupOrphanSandbox(ctx context.Context, sandboxID string) error {
	containers, err := m.client.Containers(ctx)
	if err != nil {
		return err
	}

	var errs []error
	ids := make([]string, 0)
	for _, c := range containers {
		id := c.ID()
		if strings.HasPrefix(id, sandboxID+"-") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		if e := m.stopAndDeleteContainer(ctx, id, ""); e != nil {
			errs = append(errs, e)
		}
	}

	netnsPath := filepath.Join("/run/netns", sandboxID)
	_ = network.DelSandboxNetwork(ctx, m.cni, m.netConf, sandboxID, netnsPath, nil)
	if ip := m.sandboxIPFromPauseTask(ctx, sandboxID+"-pause"); ip != "" {
		network.DeleteSandboxRules(m.ipt, sandboxID, ip, m.bridgeIF, nil)
	}

	if e := network.UnmountNetNS(netnsPath); e != nil {
		errs = append(errs, e)
	}
	_ = m.store.Delete(sandboxID)

	return errors.Join(errs...)
}

func (m *Manager) sandboxIPFromPauseTask(ctx context.Context, pauseContainerID string) string {
	ctr, err := m.client.LoadContainer(ctx, pauseContainerID)
	if err != nil {
		return ""
	}

	task, err := ctr.Task(ctx, nil)
	if err != nil {
		return ""
	}

	pid := task.Pid()
	if pid == 0 {
		return ""
	}

	out, err := exec.Command("nsenter", "-t", strconv.Itoa(int(pid)), "-n", "sh", "-c", "ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
