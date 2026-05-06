package sandbox

import (
	"time"

	"example.com/sandbox-demo/internal/model"
)

const (
	SandboxPhaseCreating = "creating"
	SandboxPhaseRunning  = "running"
	SandboxPhaseDeleting = "deleting"
	SandboxPhaseError    = "error"

	ContainerPhaseCreating = "creating"
	ContainerPhaseRunning  = "running"
	ContainerPhaseStopped  = "stopped"
	ContainerPhaseError    = "error"
	ContainerPhaseUnknown  = "unknown"
)

func (s *Service) newSandboxState(req model.CreateSandboxRequest) *model.Sandbox {
	now := time.Now().UTC()
	sbx := &model.Sandbox{
		ID:          req.ID,
		Phase:       SandboxPhaseCreating,
		Namespace:   s.namespace,
		Egress:      req.Egress,
		BridgeName:  s.bridgeIF,
		SubnetCIDR:  s.cidr,
		CNIConfPath: DefaultCNIConfPath,
		Containers:  map[string]model.ContainerState{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	sbx.Ports = append(sbx.Ports, req.Ports...)
	return sbx
}
