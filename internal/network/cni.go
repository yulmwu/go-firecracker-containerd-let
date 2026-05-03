package network

import (
	"context"
	"fmt"

	"github.com/containernetworking/cni/libcni"
	cnitypes100 "github.com/containernetworking/cni/pkg/types/100"
)

func AddSandboxNetwork(ctx context.Context, cni *libcni.CNIConfig, netConf *libcni.NetworkConfigList, sandboxID, netnsPath string, ports []map[string]any) (*cnitypes100.Result, error) {
	rt := &libcni.RuntimeConf{
		ContainerID: sandboxID,
		NetNS:       netnsPath,
		IfName:      "eth0",
		Args:        [][2]string{{"IgnoreUnknown", "1"}},
		CapabilityArgs: map[string]any{
			"portMappings": ports,
		},
	}

	res, err := cni.AddNetworkList(ctx, netConf, rt)
	if err != nil {
		return nil, err
	}

	r, err := cnitypes100.NewResultFromResult(res)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func DelSandboxNetwork(ctx context.Context, cni *libcni.CNIConfig, netConf *libcni.NetworkConfigList, sandboxID, netnsPath string, ports []map[string]any) error {
	rt := &libcni.RuntimeConf{ContainerID: sandboxID, NetNS: netnsPath, IfName: "eth0", CapabilityArgs: map[string]any{"portMappings": ports}}
	return cni.DelNetworkList(ctx, netConf, rt)
}

func ParseIPv4(result *cnitypes100.Result) (string, error) {
	for _, ip := range result.IPs {
		if ip.Address.IP.To4() != nil {
			return ip.Address.IP.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 found")
}

func GatewayIPFromResult(result *cnitypes100.Result) string {
	for _, r := range result.Routes {
		if r.GW != nil && r.GW.To4() != nil {
			return r.GW.String()
		}
	}

	return ""
}
