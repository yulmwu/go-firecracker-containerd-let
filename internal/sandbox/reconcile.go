package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

var fcnetResultRe = regexp.MustCompile(`^fcnet-(.+)-veth0$`)

// ReconcileOnce aligns state with runtime/network.
func (s *Service) ReconcileOnce(ctx context.Context) error {
	ctx = namespaces.WithNamespace(ctx, s.namespace)
	stateList, err := s.store.List()
	if err != nil {
		return err
	}

	stateMap := map[string]*model.Sandbox{}
	for _, sbx := range stateList {
		stateMap[sbx.ID] = sbx
	}

	runtimeIDs, err := s.ListRuntimeSandboxIDs(ctx)
	if err != nil {
		return err
	}

	runtimeSet := map[string]struct{}{}
	for _, id := range runtimeIDs {
		runtimeSet[id] = struct{}{}
	}

	for _, sbx := range stateList {
		if _, ok := runtimeSet[sbx.ID]; !ok {
			sbx.Phase = SandboxPhaseError
			sbx.Error = "missing runtime resources"
			sbx.UpdatedAt = time.Now().UTC()
			_ = s.store.Delete(sbx.ID)
			continue
		}

		healthy := true
		for _, c := range sbx.Containers {
			if !s.isContainerRunning(ctx, c.ID) {
				healthy = false
				break
			}
		}

		if !healthy {
			_ = s.deleteSandboxFromState(ctx, sbx)
		}
	}

	for _, runtimeID := range runtimeIDs {
		if _, ok := stateMap[runtimeID]; ok {
			continue
		}

		_ = s.cleanupOrphanRuntimeSandbox(ctx, runtimeID)
	}

	return nil
}

// StartReconcileLoop runs reconcile asynchronously until ctx is canceled.
func (s *Service) StartReconcileLoop(ctx context.Context) {
	go func() {
		t := time.NewTicker(s.cfg.ReconcileInterval)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = s.ReconcileOnce(ctx)
			}
		}
	}()
}

func (s *Service) ListRuntimeSandboxIDs(ctx context.Context) ([]string, error) {
	_ = namespaces.WithNamespace(ctx, s.namespace)
	base := "/var/lib/cni"
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}

	ids := map[string]struct{}{}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}

		resDir := filepath.Join(base, ent.Name(), "results")
		files, err := os.ReadDir(resDir)
		if err != nil {
			continue
		}

		for _, f := range files {
			mm := fcnetResultRe.FindStringSubmatch(f.Name())
			if len(mm) == 2 {
				ids[mm[1]] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}

	sort.Strings(out)
	return out, nil
}

func (s *Service) IsSandboxHealthy(ctx context.Context, sandboxID string) (bool, error) {
	ctx = namespaces.WithNamespace(ctx, s.namespace)
	sbx, err := s.store.Load(sandboxID)
	if err != nil {
		return false, err
	}

	for _, st := range sbx.Containers {
		if !s.isContainerRunning(ctx, st.ID) {
			return false, nil
		}
	}

	return true, nil
}

func (s *Service) CleanupSandboxResources(ctx context.Context, sandboxID string) error {
	ctx = namespaces.WithNamespace(ctx, s.namespace)
	sbx, err := s.store.Load(sandboxID)
	if err == nil {
		return s.deleteSandboxFromState(ctx, sbx)
	}

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return s.cleanupOrphanRuntimeSandbox(ctx, sandboxID)
}

func (s *Service) cleanupOrphanRuntimeSandbox(ctx context.Context, sandboxID string) error {
	containers, err := s.client.Containers(ctx)
	if err != nil {
		return err
	}

	tmp := &model.Sandbox{ID: sandboxID, Namespace: s.namespace, IP: s.sandboxIPFromCNICache(sandboxID), BridgeName: s.bridgeIF, Containers: map[string]model.ContainerState{}}
	for _, c := range containers {
		id := c.ID()
		if strings.HasPrefix(id, sandboxID+"-") {
			tmp.Containers[id] = model.ContainerState{ID: id}
		}
	}

	if len(tmp.Containers) == 0 && tmp.IP == "" {
		return nil
	}

	return s.deleteSandboxFromState(ctx, tmp)
}

func (s *Service) sandboxIPFromCNICache(sandboxID string) string {
	ip, err := network.LookupFCNetIPv4FromResultCache(sandboxID)
	if err != nil {
		return ""
	}

	return ip
}

func (s *Service) isContainerRunning(ctx context.Context, id string) bool {
	ctr, err := s.client.LoadContainer(ctx, id)
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
