#!/usr/bin/env bash
set -euo pipefail

CNI_VERSION="v1.9.0"
ARCH="amd64"
CONTAINERD_CONFIG="/etc/containerd/config.toml"
CNI_CONF_DIR="/etc/cni/net.d"
CNI_CONF_FILE="${CNI_CONF_DIR}/10-sandbox-demo.conflist"

log() { echo "[install] $*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }

need curl
need tar
need jq
need iptables

log "Installing base packages"
sudo apt update
sudo apt install -y iproute2 iptables curl jq tar ca-certificates gnupg apparmor apparmor-utils

if ! command -v containerd >/dev/null 2>&1; then
  log "Installing containerd.io"
  sudo apt install -y containerd.io
fi

log "Installing CNI plugins ${CNI_VERSION}"
sudo mkdir -p /opt/cni/bin
curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | sudo tar -C /opt/cni/bin -xz

log "Optional: runsc installation is skipped by default (project default runtime is runc)"

log "Preparing containerd config"
sudo mkdir -p /etc/containerd
if [ ! -f "${CONTAINERD_CONFIG}" ]; then
  containerd config default | sudo tee "${CONTAINERD_CONFIG}" >/dev/null
fi

log "Using default runtime profile: runc"

log "Restarting containerd"
sudo systemctl enable --now containerd
sudo systemctl restart containerd

log "Enabling bridge netfilter (required for sandbox-to-sandbox isolation)"
sudo modprobe br_netfilter
cat <<'CONF' | sudo tee /etc/sysctl.d/99-sandbox-demo.conf >/dev/null
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
CONF
sudo sysctl --system >/dev/null

log "Writing CNI config"
sudo mkdir -p "${CNI_CONF_DIR}" /var/lib/cni/sandbox-demo
cat <<'JSON' | sudo tee "${CNI_CONF_FILE}" >/dev/null
{
  "cniVersion": "1.0.0",
  "name": "sandbox-demo",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "sand0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": false,
      "ipam": {
        "type": "host-local",
        "ranges": [[{"subnet": "10.88.0.0/16", "gateway": "10.88.0.1"}]],
        "routes": [{"dst": "0.0.0.0/0"}],
        "dataDir": "/var/lib/cni/sandbox-demo"
      }
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    },
    {
      "type": "loopback"
    }
  ]
}
JSON

log "Ensuring iptables global chains"
sudo iptables -N SANDBOX-FWD 2>/dev/null || true
sudo iptables -C FORWARD -j SANDBOX-FWD 2>/dev/null || sudo iptables -I FORWARD 1 -j SANDBOX-FWD
sudo iptables -N SANDBOX-IN 2>/dev/null || true
sudo iptables -C INPUT -j SANDBOX-IN 2>/dev/null || sudo iptables -I INPUT 1 -j SANDBOX-IN

log "Install complete"
containerd --version
ctr version
ls /opt/cni/bin/{bridge,host-local,loopback,portmap} >/dev/null
