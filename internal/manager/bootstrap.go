package manager

import (
	"context"
	"os"
	"strings"

	"example.com/sandbox-demo/internal/network"
	sbruntime "example.com/sandbox-demo/internal/runtime"
	"example.com/sandbox-demo/internal/store"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containernetworking/cni/libcni"
	"github.com/coreos/go-iptables/iptables"
)

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

	if err := os.MkdirAll("/var/lib/sandbox-demo/state", 0o755); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(m.lockDir, 0o755); err != nil {
		return nil, err
	}

	return m, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.ToUpper(strings.TrimSpace(p))
		out = append(out, v)
	}

	return out
}
