#!/usr/bin/env bash
# Install a local Prometheus scraper and optional Alertmanager under systemd.
set -Eeuo pipefail

PROM_VERSION="${PROM_VERSION:-3.7.2}"
AM_VERSION="${AM_VERSION:-0.28.1}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/arxium-monitoring}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/arxium-monitoring}"
STATE_ROOT="${STATE_ROOT:-/var/lib/arxium-monitoring}"

log() { printf 'install-monitoring: %s\n' "$*"; }
die() { printf 'install-monitoring: error: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "run this installer with sudo"
[[ $(uname -s) == Linux ]] || die "native monitoring supports Linux only"
[[ -d /run/systemd/system ]] || die "systemd is not running"

for tool in awk curl grep install systemctl tar useradd; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "sha256sum or shasum is required to verify downloads"
fi

case "$(uname -m)" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_SRC="$SCRIPT_DIR/../prometheus"
ALERTMANAGER_CONFIG="${ALERTMANAGER_CONFIG:-$SCRIPT_DIR/alertmanager.yml}"
[[ -f "$CONFIG_SRC/prometheus.yml" ]] || die "missing $CONFIG_SRC/prometheus.yml"
[[ -f "$CONFIG_SRC/alerts.yml" ]] || die "missing $CONFIG_SRC/alerts.yml"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  log "downloading $1"
  curl --fail-with-body --silent --show-error --location --output "$2" "$1"
}

install_component() {
  local component="$1" version="$2" asset release_url expected actual extracted target
  asset="${component}-${version}.linux-${GOARCH}.tar.gz"
  release_url="https://github.com/prometheus/${component}/releases/download/v${version}"
  target="$INSTALL_ROOT/${component}-${version}"

  if [[ ! -x "$target/$component" ]]; then
    fetch "$release_url/$asset" "$tmp/$asset"
    fetch "$release_url/sha256sums.txt" "$tmp/${component}-sha256sums.txt"
    expected="$(awk -v asset="$asset" '$2 == asset { print $1 }' "$tmp/${component}-sha256sums.txt")"
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "no checksum published for $asset"
    actual="$(sha256_file "$tmp/$asset")"
    [[ "$actual" == "$expected" ]] || die "checksum mismatch for $asset"

    tar -xzf "$tmp/$asset" -C "$tmp"
    extracted="$tmp/${component}-${version}.linux-${GOARCH}"
    [[ -x "$extracted/$component" ]] || die "$asset does not contain $component"
    mkdir -p "$INSTALL_ROOT"
    mv "$extracted" "$target"
  fi

  ln -sfn "$target" "$INSTALL_ROOT/$component"
}

if ! id prometheus >/dev/null 2>&1; then
  log "creating system user prometheus"
  useradd --system --no-create-home --shell /usr/sbin/nologin prometheus
fi

install_component prometheus "$PROM_VERSION"

mkdir -p "$CONFIG_ROOT" "$STATE_ROOT/prometheus"
install -m 0644 "$CONFIG_SRC/prometheus.yml" "$CONFIG_ROOT/prometheus.yml"
install -m 0644 "$CONFIG_SRC/alerts.yml" "$CONFIG_ROOT/alerts.yml"
if [[ -f "$SCRIPT_DIR/alertmanager.yml.example" ]]; then
  install -m 0644 "$SCRIPT_DIR/alertmanager.yml.example" "$CONFIG_ROOT/alertmanager.yml.example"
fi

if [[ ${ALERTMANAGER:-0} == 1 ]]; then
  [[ -f "$ALERTMANAGER_CONFIG" ]] || die "ALERTMANAGER=1 requires a configured $ALERTMANAGER_CONFIG"
  ! grep -q 'CONFIGURE_ME' "$ALERTMANAGER_CONFIG" || die "configure an Alertmanager receiver and remove the CONFIGURE_ME marker"
  install_component alertmanager "$AM_VERSION"
  mkdir -p "$STATE_ROOT/alertmanager"
  install -o root -g prometheus -m 0640 "$ALERTMANAGER_CONFIG" "$CONFIG_ROOT/alertmanager.yml"
  "$INSTALL_ROOT/alertmanager/amtool" check-config "$CONFIG_ROOT/alertmanager.yml"

  cat >> "$CONFIG_ROOT/prometheus.yml" <<'YAML'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['127.0.0.1:9093']
YAML

  cat > /etc/systemd/system/arxium-alertmanager.service <<UNIT
[Unit]
Description=Arxium alert delivery (Alertmanager)
After=network-online.target
Wants=network-online.target

[Service]
User=prometheus
ExecStart=$INSTALL_ROOT/alertmanager/alertmanager \\
  --config.file=$CONFIG_ROOT/alertmanager.yml \\
  --storage.path=$STATE_ROOT/alertmanager \\
  --web.listen-address=127.0.0.1:9093
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$STATE_ROOT

[Install]
WantedBy=multi-user.target
UNIT
fi

"$INSTALL_ROOT/prometheus/promtool" check config "$CONFIG_ROOT/prometheus.yml"
chown -R prometheus:prometheus "$STATE_ROOT"

cat > /etc/systemd/system/arxium-prometheus.service <<UNIT
[Unit]
Description=Arxium node metrics scraper (Prometheus)
After=network-online.target arxd.service
Wants=network-online.target

[Service]
User=prometheus
ExecStart=$INSTALL_ROOT/prometheus/prometheus \\
  --config.file=$CONFIG_ROOT/prometheus.yml \\
  --storage.tsdb.path=$STATE_ROOT/prometheus \\
  --storage.tsdb.retention.time=15d \\
  --web.listen-address=127.0.0.1:9090
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$STATE_ROOT

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
if [[ ${ALERTMANAGER:-0} == 1 ]]; then
  systemctl enable arxium-alertmanager
  systemctl restart arxium-alertmanager
fi
systemctl enable arxium-prometheus
systemctl restart arxium-prometheus

attempt=1
while [[ $attempt -le 20 ]]; do
  if curl -fsS http://127.0.0.1:9090/-/ready >/dev/null; then
    log "Prometheus is ready at http://127.0.0.1:9090"
    log "view it remotely with: ssh -N -L 9090:127.0.0.1:9090 <user>@<node-host>"
    exit 0
  fi
  sleep 1
  attempt=$((attempt + 1))
done

systemctl status arxium-prometheus --no-pager >&2 || true
die "Prometheus did not become ready within 20 seconds"
