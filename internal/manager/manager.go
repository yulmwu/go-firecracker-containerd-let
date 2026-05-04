package manager

import (
	"context"
	"os"
	"sync"
	"time"

	sbruntime "example.com/sandbox-demo/internal/runtime"
	"example.com/sandbox-demo/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containernetworking/cni/libcni"
	"github.com/coreos/go-iptables/iptables"
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

func csvEnv(key string, def []string) []string {
	raw := os.Getenv(key)
	if raw == "" {
		return append([]string(nil), def...)
	}

	out := make([]string, 0)
	for _, p := range splitCSV(raw) {
		if p == "" {
			continue
		}
		out = append(out, p)
	}

	if len(out) == 0 {
		return append([]string(nil), def...)
	}

	return out
}
