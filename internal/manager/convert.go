package manager

import (
	"os"
	"path/filepath"
	"strings"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/network"
	"golang.org/x/sys/unix"
)

func toCNIPorts(in []model.PortMapping) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, p := range in {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		out = append(out, map[string]any{"hostPort": p.HostPort, "containerPort": p.ContainerPort, "protocol": proto})
	}

	return out
}

func toPublishedPorts(in []model.PortMapping) []network.PublishedPort {
	out := make([]network.PublishedPort, 0, len(in))
	for _, p := range in {
		out = append(out, network.PublishedPort{ContainerPort: p.ContainerPort, Protocol: p.Protocol})
	}

	return out
}

func (m *Manager) acquireSandboxLock(id string) (func(), error) {
	lockPath := filepath.Join(m.lockDir, id+".lock")
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
