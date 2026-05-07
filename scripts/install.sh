#!/usr/bin/env bash
set -euo pipefail

CNI_VERSION="v1.9.0"
ARCH="amd64"
FC_CONTD_REPO="https://github.com/firecracker-microvm/firecracker-containerd.git"
FC_SRC_DIR="/tmp/firecracker-containerd-src"
FC_RUNTIME_DIR="/var/lib/firecracker-containerd/runtime"
FC_KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
FC_DM_POOL="sandbox-devpool"
FC_CNI_CONF_DIR="/etc/cni/net.d"
FC_CNI_CONF_FILE="${FC_CNI_CONF_DIR}/20-fcnet.conflist"

log() { echo "[install] $*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1"; exit 1; }; }
die() { echo "[install] ERROR: $*" >&2; exit 1; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%s)"
  sudo cp -a "$f" "${f}.bak.${ts}"
}

isolate_system_containerd() {
  # Never inject firecracker snapshotter config into system containerd used by Docker.
  local bad="/etc/containerd/conf.d/99-firecracker-devmapper.toml"
  if [[ -f "$bad" ]]; then
    log "Moving conflicting system containerd snippet: $bad"
    sudo mkdir -p /etc/containerd/conf.d.disabled
    sudo mv "$bad" "/etc/containerd/conf.d.disabled/99-firecracker-devmapper.toml.bak"
  fi
}

preflight_checks() {
  need sudo
  need systemctl
  need awk
  need sed

  # Refuse to proceed if there are unknown firecracker snippets in system containerd conf.d.
  local unknown
  unknown="$(sudo find /etc/containerd/conf.d -maxdepth 1 -type f -name '*firecracker*' ! -name '99-firecracker-devmapper.toml' 2>/dev/null || true)"
  if [[ -n "$unknown" ]]; then
    echo "$unknown" >&2
    die "unexpected firecracker snippets found in /etc/containerd/conf.d; clean up first"
  fi
}

install_base() {
  need curl
  need tar
  need jq
  need iptables

  log "Installing base packages"
  sudo apt update
  sudo apt install -y iproute2 iptables curl jq tar ca-certificates gnupg apparmor apparmor-utils git make gcc bc squashfs-tools debootstrap thin-provisioning-tools lvm2

  if ! command -v containerd >/dev/null 2>&1; then
    log "Installing containerd.io"
    sudo apt install -y containerd.io
  fi
  log "Ensuring containerd service is running"
  sudo systemctl enable --now containerd
  sudo systemctl is-active containerd >/dev/null || die "containerd failed to start"

  log "Installing CNI plugins ${CNI_VERSION}"
  sudo mkdir -p /opt/cni/bin
  curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" | sudo tar -C /opt/cni/bin -xz

  log "Enabling bridge netfilter"
  sudo modprobe br_netfilter
  cat <<'CONF' | sudo tee /etc/sysctl.d/99-sandbox-demo.conf >/dev/null
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
CONF
  sudo sysctl --system >/dev/null

  log "Ensuring iptables global chains"
  sudo iptables -N SANDBOX-FWD 2>/dev/null || true
  sudo iptables -C FORWARD -j SANDBOX-FWD 2>/dev/null || sudo iptables -I FORWARD 1 -j SANDBOX-FWD
  sudo iptables -N SANDBOX-IN 2>/dev/null || true
  sudo iptables -C INPUT -j SANDBOX-IN 2>/dev/null || sudo iptables -I INPUT 1 -j SANDBOX-IN
}

ensure_firecracker_devpool() {
  local pool="/dev/mapper/${FC_DM_POOL}"
  if [[ ! -e "$pool" ]]; then
    echo "firecracker devmapper pool is not ready: $pool" >&2
    exit 1
  fi
}

install_firecracker() {
  log "Installing Firecracker binaries"
  local fc_ver
  fc_ver="$(curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | jq -r '.tag_name')"
  curl -fsSL -o /tmp/firecracker.tgz "https://github.com/firecracker-microvm/firecracker/releases/download/${fc_ver}/firecracker-${fc_ver}-x86_64.tgz"
  tar -xzf /tmp/firecracker.tgz -C /tmp
  sudo install -m 755 "/tmp/release-${fc_ver}-x86_64/firecracker-${fc_ver}-x86_64" /usr/local/bin/firecracker
  sudo install -m 755 "/tmp/release-${fc_ver}-x86_64/jailer-${fc_ver}-x86_64" /usr/local/bin/jailer

  log "Building firecracker containerd shim"
  rm -rf "${FC_SRC_DIR}"
  git clone --depth 1 "${FC_CONTD_REPO}" "${FC_SRC_DIR}"
  make -C "${FC_SRC_DIR}/runtime"
  sudo install -m 755 "${FC_SRC_DIR}/runtime/containerd-shim-aws-firecracker" /usr/local/bin/containerd-shim-aws-firecracker

  log "Building firecracker-containerd daemon and CLI"
  make -C "${FC_SRC_DIR}/firecracker-control/cmd/containerd" build
  sudo install -m 755 "${FC_SRC_DIR}/firecracker-control/cmd/containerd/firecracker-containerd" /usr/local/bin/firecracker-containerd
  sudo install -m 755 "${FC_SRC_DIR}/firecracker-control/cmd/containerd/firecracker-ctr" /usr/local/bin/firecracker-ctr
  log "Installing tc-redirect-tap CNI plugin"
  sudo env GOBIN=/opt/cni/bin go install github.com/awslabs/tc-redirect-tap/cmd/tc-redirect-tap@v0.0.0-20250516183331-34bf829e9a5c

  log "Building Firecracker VM rootfs image"
  make -C "${FC_SRC_DIR}" image
  sudo mkdir -p "${FC_RUNTIME_DIR}"
  sudo cp "${FC_SRC_DIR}/tools/image-builder/rootfs.img" "${FC_RUNTIME_DIR}/default-rootfs.img"

  log "Downloading Firecracker kernel image"
  curl -fsSL -o /tmp/default-vmlinux.bin "${FC_KERNEL_URL}"
  sudo cp /tmp/default-vmlinux.bin "${FC_RUNTIME_DIR}/default-vmlinux.bin"

  log "Writing /etc/containerd/firecracker-runtime.json"
  sudo mkdir -p /etc/containerd
  cat <<'JSON' | sudo tee /etc/containerd/firecracker-runtime.json >/dev/null
{
  "firecracker_binary_path": "/usr/local/bin/firecracker",
  "kernel_image_path": "/var/lib/firecracker-containerd/runtime/default-vmlinux.bin",
  "kernel_args": "console=ttyS0 noapic reboot=k panic=1 pci=off nomodules ro systemd.unified_cgroup_hierarchy=0 systemd.journald.forward_to_console systemd.unit=firecracker.target init=/sbin/overlay-init",
  "root_drive": "/var/lib/firecracker-containerd/runtime/default-rootfs.img",
  "cpu_template": "",
  "default_network_interfaces": [{
    "CNIConfig": {
      "NetworkName": "fcnet",
      "InterfaceName": "veth0",
      "ConfDir": "/etc/cni/net.d",
      "BinPath": ["/opt/cni/bin"]
    }
  }],
  "log_fifo": "fc-logs.fifo",
  "log_levels": ["debug"],
  "metrics_fifo": "fc-metrics.fifo"
}
JSON

  log "Writing firecracker CNI config (fcnet)"
  sudo mkdir -p "${FC_CNI_CONF_DIR}" /var/lib/cni/fcnet
  cat <<'JSON' | sudo tee "${FC_CNI_CONF_FILE}" >/dev/null
{
  "cniVersion": "1.0.0",
  "name": "fcnet",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "fc-br0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{"subnet": "10.89.0.0/16", "gateway": "10.89.0.1"}]],
        "routes": [{"dst": "0.0.0.0/0"}],
        "dataDir": "/var/lib/cni/fcnet"
      }
    },
    {
      "type": "firewall"
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    },
    {
      "type": "tc-redirect-tap"
    },
    {
      "type": "loopback"
    }
  ]
}
JSON

  log "Preparing devmapper thin-pool for firecracker snapshotter"
  sudo FICD_DM_POOL="${FC_DM_POOL}" bash "${FC_SRC_DIR}/tools/thinpool.sh" create "${FC_DM_POOL}"
  ensure_firecracker_devpool

  log "Writing /etc/firecracker-containerd/config.toml"
  sudo mkdir -p /etc/firecracker-containerd /var/lib/firecracker-containerd/containerd /run/firecracker-containerd
  cat <<TOML | sudo tee /etc/firecracker-containerd/config.toml >/dev/null
version = 2
disabled_plugins = ["io.containerd.grpc.v1.cri"]
root = "/var/lib/firecracker-containerd/containerd"
state = "/run/firecracker-containerd"

[grpc]
  address = "/run/firecracker-containerd/containerd.sock"

[plugins."io.containerd.snapshotter.v1.devmapper"]
  pool_name = "${FC_DM_POOL}"
  base_image_size = "1024MB"

[debug]
  level = "info"
TOML

  log "Installing and starting firecracker-containerd service"
  cat <<'UNIT' | sudo tee /etc/systemd/system/firecracker-containerd.service >/dev/null
[Unit]
Description=Firecracker containerd daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/firecracker-containerd --config /etc/firecracker-containerd/config.toml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now firecracker-containerd
  sudo systemctl is-active firecracker-containerd >/dev/null || die "firecracker-containerd failed to start"
}

write_runtime_env() {
  log "Writing Firecracker runtime settings to .env"
  local runtime_addr="/run/firecracker-containerd/containerd.sock"

  if [[ -f .env ]]; then
    sed -i '/^SANDBOX_RUNTIME_PROFILE=/d' .env
    if grep -q '^SANDBOX_CONTAINERD_ADDRESS=' .env; then
      sed -i "s|^SANDBOX_CONTAINERD_ADDRESS=.*|SANDBOX_CONTAINERD_ADDRESS=${runtime_addr}|" .env
    else
      echo "SANDBOX_CONTAINERD_ADDRESS=${runtime_addr}" >> .env
    fi
    sed -i '/^SANDBOX_SNAPSHOTTER=/d' .env
  else
    cat > .env <<ENV
SANDBOX_CONTAINERD_ADDRESS=${runtime_addr}
ENV
  fi
}

main() {
  preflight_checks
  isolate_system_containerd
  install_base
  install_firecracker
  write_runtime_env

  log "Install complete"
  containerd --version
  ctr version
  ls /opt/cni/bin/{bridge,host-local,loopback,portmap} >/dev/null
  command -v firecracker >/dev/null
  command -v containerd-shim-aws-firecracker >/dev/null
  log "Runtime: firecracker"
}

main "$@"
