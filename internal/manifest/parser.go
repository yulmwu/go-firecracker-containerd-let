package manifest

import (
	"fmt"
	"os"
	"strings"

	"example.com/sandbox-demo/internal/model"
	"gopkg.in/yaml.v3"
)

func ParseFile(path string) (model.CreateSandboxRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return model.CreateSandboxRequest{}, err
	}

	var mf model.SandboxManifest
	if err := yaml.Unmarshal(b, &mf); err != nil {
		return model.CreateSandboxRequest{}, err
	}

	if strings.ToLower(mf.Kind) != "sandbox" {
		return model.CreateSandboxRequest{}, fmt.Errorf("manifest kind must be Sandbox")
	}

	if mf.Metadata.Name == "" {
		return model.CreateSandboxRequest{}, fmt.Errorf("manifest metadata.name is required")
	}

	req := model.CreateSandboxRequest{
		ID:         mf.Metadata.Name,
		Egress:     mf.Spec.Egress,
		Ports:      mf.Spec.Ports,
		Containers: mf.Spec.Containers,
	}
	return req, req.Validate()
}
