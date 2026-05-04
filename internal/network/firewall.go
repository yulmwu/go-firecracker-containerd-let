package network

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

type PublishedPort struct {
	ContainerPort int
	Protocol      string
}

// EnsureGlobalChains installs global jump points for sandbox firewalling.
//
// Design:
// - SANDBOX-FWD: egress policy entrypoint for each sandbox source IP.
// - SANDBOX-IN: ingress policy entrypoint for traffic entering from sandbox bridge.
//
// forwardHookChains lets us hook SANDBOX-FWD from multiple parent chains
// (e.g. FORWARD, DOCKER-USER, custom chains) without hardcoding Docker.
func EnsureGlobalChains(ipt *iptables.IPTables, forwardHookChains []string) error {
	// Create shared chains once; ignore "already exists" errors.
	_ = ipt.NewChain("filter", "SANDBOX-FWD")
	_ = ipt.NewChain("filter", "SANDBOX-IN")

	// CNI portmap marks DNAT traffic with 0x2000. This must be accepted early
	// so hostPort traffic is not dropped before per-sandbox rules evaluate.
	if err := insertFirst(ipt, "FORWARD", []string{"-m", "mark", "--mark", "0x2000/0x2000", "-j", "ACCEPT"}); err != nil {
		return err
	}

	// Keep conntrack return path stable for established flows.
	if err := insertFirst(ipt, "FORWARD", []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}); err != nil {
		return err
	}

	// Always guarantee FORWARD hook exists even if caller omitted it.
	if len(forwardHookChains) == 0 {
		forwardHookChains = []string{"FORWARD"}
	}

	if !containsChain(forwardHookChains, "FORWARD") {
		forwardHookChains = append([]string{"FORWARD"}, forwardHookChains...)
	}

	// Install SANDBOX-FWD jump at the top of each requested parent chain.
	// Non-existent chains are skipped to avoid host-specific coupling.
	for _, chain := range forwardHookChains {
		chain = strings.TrimSpace(strings.ToUpper(chain))
		if chain == "" || !hasChain(ipt, chain) {
			continue
		}

		if err := insertFirst(ipt, chain, []string{"-j", "SANDBOX-FWD"}); err != nil {
			return err
		}
	}

	// Route host INPUT into SANDBOX-IN for host-originated/host-destined checks.
	if err := insertFirst(ipt, "INPUT", []string{"-j", "SANDBOX-IN"}); err != nil {
		return err
	}

	return nil
}

// ApplySandboxRules creates per-sandbox chains and attaches them to global chains.
// The policy is source-IP based so each sandbox gets isolated egress control.
func ApplySandboxRules(ipt *iptables.IPTables, sandboxID, ip, bridgeCIDR, bridgeIF string, egress bool, ports []PublishedPort) error {
	short := shortID(sandboxID)
	fwd := "SBX-" + short + "-FWD"
	in := "SBX-" + short + "-IN"

	// Per-sandbox chains.
	_ = ipt.NewChain("filter", fwd)
	_ = ipt.NewChain("filter", in)

	// Traffic FROM sandbox source IP goes through sandbox forward policy.
	if err := ipt.AppendUnique("filter", "SANDBOX-FWD", "-s", ip+"/32", "-j", fwd); err != nil {
		return err
	}

	// Traffic entering from bridge interface and sourced by sandbox IP
	// goes through sandbox ingress policy chain.
	if err := ipt.AppendUnique("filter", "SANDBOX-IN", "-i", bridgeIF, "-s", ip+"/32", "-j", in); err != nil {
		return err
	}

	// Explicitly allow forwarded packets targeting published container ports.
	// Port DNAT is handled by CNI portmap (nat table); this ACCEPT prevents
	// filter/FORWARD from dropping those forwarded packets.
	for _, p := range ports {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		_ = ipt.AppendUnique("filter", "FORWARD", "-d", ip+"/32", "-p", proto, "--dport", fmt.Sprintf("%d", p.ContainerPort), "-j", "ACCEPT")
	}

	// Allow return traffic for already-established connections first.
	_ = ipt.AppendUnique("filter", fwd, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	// With egress enabled, allow DNS queries to configured resolvers before
	// private-range deny rules so package installs/name resolution still work.
	if egress {
		for _, ns := range systemNameservers() {
			_ = ipt.AppendUnique("filter", fwd, "-d", ns, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
			_ = ipt.AppendUnique("filter", fwd, "-d", ns, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
		}
	}

	// Deny internal/reserved ranges to prevent lateral movement and host/local
	// network reachability from sandbox workloads.
	for _, cidr := range []string{
		bridgeCIDR,
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	} {
		_ = ipt.AppendUnique("filter", fwd, "-d", cidr, "-j", "REJECT")
	}

	// Default egress stance.
	if egress {
		_ = ipt.AppendUnique("filter", fwd, "-j", "ACCEPT")
	} else {
		_ = ipt.AppendUnique("filter", fwd, "-j", "REJECT")
	}

	// Ingress chain: only return packets are allowed, everything else rejected.
	// This keeps host-facing ingress narrow by default.
	_ = ipt.AppendUnique("filter", in, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	_ = ipt.AppendUnique("filter", in, "-j", "REJECT")

	return nil
}

// DeleteSandboxRules removes per-sandbox hooks and chains.
// Order matters: detach jumps first, then clear/delete chains.
func DeleteSandboxRules(ipt *iptables.IPTables, sandboxID, ip, bridgeIF string, ports []PublishedPort) {
	short := shortID(sandboxID)
	fwd := "SBX-" + short + "-FWD"
	in := "SBX-" + short + "-IN"

	// Remove hostPort forward ACCEPTs for this sandbox.
	for _, p := range ports {
		proto := strings.ToLower(p.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		_ = ipt.Delete("filter", "FORWARD", "-d", ip+"/32", "-p", proto, "--dport", fmt.Sprintf("%d", p.ContainerPort), "-j", "ACCEPT")
	}

	// Detach from global chains.
	_ = ipt.Delete("filter", "SANDBOX-FWD", "-s", ip+"/32", "-j", fwd)
	_ = ipt.Delete("filter", "SANDBOX-IN", "-i", bridgeIF, "-s", ip+"/32", "-j", in)

	// Clear and remove dedicated chains.
	_ = ipt.ClearChain("filter", fwd)
	_ = ipt.ClearChain("filter", in)
	_ = ipt.DeleteChain("filter", fwd)
	_ = ipt.DeleteChain("filter", in)
}

// insertFirst keeps rule priority deterministic by re-inserting at position 1.
// Deleting first prevents duplicates from repeated reconcile/create runs.
func insertFirst(ipt *iptables.IPTables, parent string, rule []string) error {
	_ = ipt.Delete("filter", parent, rule...)
	if err := ipt.Insert("filter", parent, 1, rule...); err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}

	return nil
}

func shortID(id string) string {
	// Use deterministic hash-based suffix to avoid chain name collisions
	// between sandbox IDs that share the same prefix.
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return fmt.Sprintf("%08x", h.Sum32())
}

func hasChain(ipt *iptables.IPTables, chain string) bool {
	chains, err := ipt.ListChains("filter")
	if err != nil {
		return false
	}

	return slices.Contains(chains, chain)
}

// containsChain checks case-insensitively for env-provided chain names.
func containsChain(chains []string, target string) bool {
	target = strings.ToUpper(strings.TrimSpace(target))
	for _, c := range chains {
		if strings.ToUpper(strings.TrimSpace(c)) == target {
			return true
		}
	}

	return false
}

func systemNameservers() []string {
	path := "/etc/resolv.conf"
	// systemd-resolved hosts often expose 127.0.0.53 in /etc/resolv.conf.
	// Prefer the upstream resolver list to build reachable DNS allow-rules.
	if st, err := os.Stat("/run/systemd/resolve/resolv.conf"); err == nil && !st.IsDir() {
		path = "/run/systemd/resolve/resolv.conf"
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}

		ip := net.ParseIP(fields[1])
		if ip == nil || ip.To4() == nil {
			continue
		}

		s := ip.String() + "/32"
		if _, ok := seen[s]; ok {
			continue
		}

		seen[s] = struct{}{}
		out = append(out, s)
	}

	return out
}
