package model

type SandboxManifest struct {
	APIVersion string              `yaml:"apiVersion"`
	Kind       string              `yaml:"kind"`
	Metadata   ManifestMetadata    `yaml:"metadata"`
	Spec       SandboxManifestSpec `yaml:"spec"`
}

type ManifestMetadata struct {
	Name string `yaml:"name"`
}

type SandboxManifestSpec struct {
	Egress     bool                     `yaml:"egress"`
	Ports      []PortMapping            `yaml:"ports"`
	Containers []CreateContainerRequest `yaml:"containers"`
}
