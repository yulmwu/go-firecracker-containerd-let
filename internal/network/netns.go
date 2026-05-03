package network

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func BindMountNetNS(pid uint32, sandboxID string) (string, error) {
	target := filepath.Join("/run/netns", sandboxID)
	source := fmt.Sprintf("/proc/%d/ns/net", pid)
	if err := os.MkdirAll("/run/netns", 0o755); err != nil {
		return "", err
	}

	_ = os.Remove(target)
	f, err := os.OpenFile(target, os.O_CREATE, 0o644)
	if err != nil {
		return "", err
	}

	_ = f.Close()
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return "", fmt.Errorf("bind mount failed: %w", err)
	}

	return target, nil
}

func UnmountNetNS(path string) error {
	if err := unix.Unmount(path, 0); err != nil {
		if _, stErr := os.Stat(path); os.IsNotExist(stErr) {
			return nil
		}

		return fmt.Errorf("umount failed: %w", err)
	}

	_ = os.Remove(path)
	return nil
}
