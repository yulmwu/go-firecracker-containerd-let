package runtime

import (
	"fmt"
	"strings"
)

type Profile struct {
	Name        string
	RuntimeType string
	Description string
}

var profiles = map[string]Profile{
	"runc": {
		Name:        "runc",
		RuntimeType: "io.containerd.runc.v2",
		Description: "Default OCI runtime; good compatibility.",
	},
	"runsc": {
		Name:        "runsc",
		RuntimeType: "io.containerd.runsc.v1",
		Description: "gVisor sandbox runtime.",
	},
	"kata": {
		Name:        "kata",
		RuntimeType: "io.containerd.kata.v2",
		Description: "Kata Containers runtime placeholder.",
	},
	"firecracker": {
		Name:        "firecracker",
		RuntimeType: "io.containerd.firecracker.v2",
		Description: "Firecracker runtime placeholder.",
	},
}

func Resolve(name string) (Profile, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		n = "runc"
	}

	p, ok := profiles[n]
	if !ok {
		return Profile{}, fmt.Errorf("unknown runtime profile %q", name)
	}

	return p, nil
}
