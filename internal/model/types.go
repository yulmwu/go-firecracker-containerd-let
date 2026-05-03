package model

import "time"

type Sandbox struct {
	ID          string                    `json:"id"`
	Namespace   string                    `json:"namespace"`
	NetNSPath   string                    `json:"netNSPath"`
	IP          string                    `json:"ip"`
	GatewayIP   string                    `json:"gatewayIP"`
	SubnetCIDR  string                    `json:"subnetCIDR"`
	BridgeName  string                    `json:"bridgeName"`
	Egress      bool                      `json:"egress"`
	Ports       []PortMapping             `json:"ports,omitempty"`
	Pause       ContainerState            `json:"pause"`
	Containers  map[string]ContainerState `json:"containers"`
	CNIConfPath string                    `json:"cniConfPath"`
	CreatedAt   time.Time                 `json:"createdAt"`
}

type ContainerState struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Args        []string `json:"args,omitempty"`
	Env         []string `json:"env,omitempty"`
	SnapshotKey string   `json:"snapshotKey"`
	TaskPID     uint32   `json:"taskPID"`
	Runtime     string   `json:"runtime"`
	TaskStatus  string   `json:"taskStatus,omitempty"`
	ExitStatus  uint32   `json:"exitStatus,omitempty"`
	ExitTime    string   `json:"exitTime,omitempty"`
}

type CreateSandboxRequest struct {
	ID         string                   `json:"id" yaml:"id"`
	Egress     bool                     `json:"egress" yaml:"egress"`
	Containers []CreateContainerRequest `json:"containers" yaml:"containers"`
	Ports      []PortMapping            `json:"ports" yaml:"ports"`
}

type CreateContainerRequest struct {
	Name    string         `json:"name" yaml:"name"`
	Image   string         `json:"image" yaml:"image"`
	Args    []string       `json:"args" yaml:"args"`
	Env     []string       `json:"env" yaml:"env"`
	WorkDir string         `json:"workDir" yaml:"workDir"`
	Limits  ResourceLimits `json:"limits" yaml:"limits"`
}

type ResourceLimits struct {
	MemoryBytes int64  `json:"memoryBytes" yaml:"memoryBytes"`
	CPUQuota    int64  `json:"cpuQuota" yaml:"cpuQuota"`
	CPUPeriod   uint64 `json:"cpuPeriod" yaml:"cpuPeriod"`
	PidsLimit   int64  `json:"pidsLimit" yaml:"pidsLimit"`
}

type PortMapping struct {
	HostPort      int    `json:"hostPort" yaml:"hostPort"`
	ContainerPort int    `json:"containerPort" yaml:"containerPort"`
	Protocol      string `json:"protocol" yaml:"protocol"`
}
