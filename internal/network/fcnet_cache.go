package network

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

type cniCacheFile struct {
	Result struct {
		IPs []struct {
			Address string `json:"address"`
		} `json:"ips"`
	} `json:"result"`
}

// LookupFCNetIPv4FromResultCache reads fcnet CNI result cache for a sandbox/VM id
// and returns the assigned IPv4 address.
func LookupFCNetIPv4FromResultCache(sandboxID string) (string, error) {
	if sandboxID == "" {
		return "", fmt.Errorf("sandbox id is required")
	}

	cachePath := filepath.Join("/var/lib/cni", sandboxID, "results", "fcnet-"+sandboxID+"-veth0")
	b, err := os.ReadFile(cachePath)
	if err != nil {
		return "", err
	}

	var cf cniCacheFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return "", fmt.Errorf("parse cni cache %s: %w", cachePath, err)
	}

	for _, ip := range cf.Result.IPs {
		pfx, err := netip.ParsePrefix(ip.Address)
		if err != nil {
			continue
		}

		addr := pfx.Addr()
		if addr.Is4() {
			return addr.String(), nil
		}
	}

	return "", fmt.Errorf("no ipv4 in cni cache: %s", cachePath)
}
