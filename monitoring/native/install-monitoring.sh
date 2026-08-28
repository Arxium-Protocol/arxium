#!/usr/bin/env bash
# Install Prometheus, Grafana, and optional Alertmanager under systemd.
set -Eeuo pipefail

PROM_VERSION="${PROM_VERSION:-3.7.2}"
AM_VERSION="${AM_VERSION:-0.28.1}"
GRAFANA_VERSION="${GRAFANA_VERSION:-12.1.4}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/arxium-monitoring}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/arxium-monitoring}"
STATE_ROOT="${STATE_ROOT:-/var/lib/arxium-monitoring}"
GRAFANA_INPUT_ATTEMPTS="${GRAFANA_INPUT_ATTEMPTS:-3}"

log() { printf 'install-monitoring: %s\n' "$*"; }
die() { printf 'install-monitoring: error: %s\n' "$*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || die "run this installer with sudo"
[[ $(uname -s) == Linux ]] || die "native monitoring supports Linux only"
[[ -d /run/systemd/system ]] || die "systemd is not running"

for tool in awk cp curl cut find grep head install nft od openssl readlink systemctl tar tr useradd; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

[[ $GRAFANA_INPUT_ATTEMPTS =~ ^[1-9][0-9]*$ && $GRAFANA_INPUT_ATTEMPTS -le 10 ]] \
  || die "GRAFANA_INPUT_ATTEMPTS must be between 1 and 10"

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
GRAFANA_SRC="$SCRIPT_DIR/../grafana"
GRAFANA_CONFIG_ROOT="$CONFIG_ROOT/grafana"
GRAFANA_STATE_ROOT="$STATE_ROOT/grafana"
GRAFANA_ENV="$CONFIG_ROOT/grafana.env"
GRAFANA_BOOTSTRAP_ENV="$CONFIG_ROOT/grafana-bootstrap.env"
GRAFANA_ADMIN_USER_FILE="$CONFIG_ROOT/grafana-admin-user"
GRAFANA_PUBLIC_HOST_FILE="$CONFIG_ROOT/grafana-public-host"
GRAFANA_INITIALIZED="$CONFIG_ROOT/grafana-initialized"
GRAFANA_CERT="$GRAFANA_CONFIG_ROOT/grafana.crt"
GRAFANA_KEY="$GRAFANA_CONFIG_ROOT/grafana.key"
ALERTMANAGER_CONFIG="${ALERTMANAGER_CONFIG:-$SCRIPT_DIR/alertmanager.yml}"
if [[ -z ${ALERTMANAGER+x} \
  && -f "$CONFIG_ROOT/alertmanager.yml" \
  && -f /etc/systemd/system/arxium-alertmanager.service ]]; then
  ALERTMANAGER=1
  ALERTMANAGER_CONFIG="$CONFIG_ROOT/alertmanager.yml"
fi
ALERTMANAGER="${ALERTMANAGER:-0}"
[[ -f "$CONFIG_SRC/prometheus.yml" ]] || die "missing $CONFIG_SRC/prometheus.yml"
[[ -f "$CONFIG_SRC/alerts.yml" ]] || die "missing $CONFIG_SRC/alerts.yml"
[[ -f "$GRAFANA_SRC/provisioning/datasources/prometheus.yml" ]] || die "missing Grafana datasource provisioning"
[[ -f "$GRAFANA_SRC/provisioning/dashboards/provider.yml" ]] || die "missing Grafana dashboard provisioning"
[[ -f "$GRAFANA_SRC/dashboards/arxium-node.json" ]] || die "missing Arxium Grafana dashboard"

if [[ -f "$GRAFANA_INITIALIZED" && ! -s "$GRAFANA_STATE_ROOT/data/grafana.db" ]]; then
  systemctl stop arxium-grafana >/dev/null 2>&1 || true
  die "Grafana initialization marker exists without its database; service stopped to prevent a public default account. Restore $GRAFANA_STATE_ROOT/data before reinstalling"
fi

tmp="$(mktemp -d)"
bootstrap_pending=0
transaction_active=0
grafana_was_active=0
prometheus_was_active=0
alertmanager_was_active=0
grafana_was_enabled=0
prometheus_was_enabled=0
alertmanager_was_enabled=0
had_config_root=0
had_grafana_data=0
config_root_existed=0
grafana_data_existed=0
old_prometheus_target=""
old_grafana_target=""
old_alertmanager_target=""

restore_link() {
  local name="$1" target="$2"
  if [[ -n "$target" ]]; then
    ln -sfn "$target" "$INSTALL_ROOT/$name"
  else
    rm -f "$INSTALL_ROOT/$name"
  fi
}

rollback_monitoring() {
  set +e
  log "validation failed; restoring the previous monitoring installation"
  systemctl stop arxium-grafana arxium-prometheus arxium-alertmanager >/dev/null 2>&1
  systemctl disable arxium-grafana arxium-prometheus arxium-alertmanager >/dev/null 2>&1
  restore_link prometheus "$old_prometheus_target"
  restore_link grafana "$old_grafana_target"
  restore_link alertmanager "$old_alertmanager_target"

  if [[ $had_config_root -eq 1 ]]; then
    rm -rf "$CONFIG_ROOT"
    cp -a "$tmp/config-backup" "$CONFIG_ROOT"
  elif [[ $config_root_existed -eq 0 ]]; then
    rm -rf "$CONFIG_ROOT"
  fi
  if [[ $had_grafana_data -eq 1 ]]; then
    rm -rf "$STATE_ROOT/grafana/data"
    mkdir -p "$STATE_ROOT/grafana"
    cp -a "$tmp/grafana-data-backup" "$STATE_ROOT/grafana/data"
  elif [[ $grafana_data_existed -eq 0 ]]; then
    rm -rf "$STATE_ROOT/grafana/data"
  fi

  for unit in arxium-prometheus arxium-grafana arxium-alertmanager; do
    if [[ -f "$tmp/$unit.service" ]]; then
      cp -a "$tmp/$unit.service" "/etc/systemd/system/$unit.service"
    else
      rm -f "/etc/systemd/system/$unit.service"
    fi
  done
  nft list table inet arxium_grafana >/dev/null 2>&1 \
    && nft delete table inet arxium_grafana
  systemctl daemon-reload
  [[ $prometheus_was_enabled -eq 1 ]] && systemctl enable arxium-prometheus
  [[ $alertmanager_was_enabled -eq 1 ]] && systemctl enable arxium-alertmanager
  [[ $grafana_was_enabled -eq 1 ]] && systemctl enable arxium-grafana
  [[ $prometheus_was_active -eq 1 ]] && systemctl restart arxium-prometheus
  [[ $alertmanager_was_active -eq 1 ]] && systemctl restart arxium-alertmanager
  [[ $grafana_was_active -eq 1 ]] && systemctl restart arxium-grafana
}

cleanup() {
  local status=$?
  if [[ $bootstrap_pending -eq 1 ]]; then
    systemctl stop arxium-grafana >/dev/null 2>&1 || true
    rm -f "${GRAFANA_BOOTSTRAP_ENV:-}"
  fi
  if [[ $status -ne 0 && $transaction_active -eq 1 ]]; then
    rollback_monitoring
  fi
  rm -rf "$tmp"
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
    rm -rf "$target"
    mv "$extracted" "$target"
  fi

}

install_grafana() {
  local asset url expected actual extracted target extract_root
  asset="grafana-${GRAFANA_VERSION}.linux-${GOARCH}.tar.gz"
  url="https://dl.grafana.com/oss/release/$asset"
  target="$INSTALL_ROOT/grafana-${GRAFANA_VERSION}"

  if [[ ! -x "$target/bin/grafana" ]]; then
    fetch "$url" "$tmp/$asset"
    fetch "$url.sha256" "$tmp/$asset.sha256"
    expected="$(tr -d '[:space:]' < "$tmp/$asset.sha256")"
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "no valid checksum published for $asset"
    actual="$(sha256_file "$tmp/$asset")"
    [[ "$actual" == "$expected" ]] || die "checksum mismatch for $asset"

    extract_root="$tmp/grafana-extract"
    mkdir -p "$extract_root"
    tar -xzf "$tmp/$asset" -C "$extract_root"
    extracted="$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | head -1)"
    [[ -n "$extracted" && -x "$extracted/bin/grafana" ]] || die "$asset does not contain Grafana"
    mkdir -p "$INSTALL_ROOT"
    rm -rf "$target"
    mv "$extracted" "$target"
  fi

}

valid_ipv4() {
  local ip="$1" octet
  local -a octets
  IFS=. read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

valid_dns_name() {
  local name="$1" label
  local -a labels
  [[ ${#name} -le 253 && $name != *..* ]] || return 1
  IFS=. read -r -a labels <<< "$name"
  for label in "${labels[@]}"; do
    [[ ${#label} -ge 1 && ${#label} -le 63 ]] || return 1
    [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done
}

valid_grafana_username() {
  [[ $1 =~ ^[A-Za-z0-9._-]{1,64}$ ]]
}

validate_grafana_password() {
  local password="$1" confirmation="$2"
  grafana_password_error=""
  if [[ "$password" != "$confirmation" ]]; then
    grafana_password_error="Grafana passwords do not match"
  elif [[ ${#password} -lt 12 ]]; then
    grafana_password_error="Grafana password must be at least 12 characters"
  elif [[ ! $password =~ [a-z] \
    || ! $password =~ [A-Z] \
    || ! $password =~ [0-9] \
    || ! $password =~ [^A-Za-z0-9] ]]; then
    grafana_password_error="Grafana password must include lowercase, uppercase, numeric, and special characters"
  elif [[ $password == *[[:space:]\\\"\']* ]]; then
    grafana_password_error="Grafana password cannot contain whitespace, backslash, or quote characters"
  fi
  [[ -z $grafana_password_error ]]
}

retry_message() {
  local message="$1" attempt="$2"
  printf 'install-monitoring: error: %s (%d attempt(s) remaining)\n' \
    "$message" "$((GRAFANA_INPUT_ATTEMPTS - attempt))" >&2
}

if ! id prometheus >/dev/null 2>&1; then
  log "creating system user prometheus"
  useradd --system --no-create-home --shell /usr/sbin/nologin prometheus
fi
if ! id grafana >/dev/null 2>&1; then
  log "creating system user grafana"
  useradd --system --no-create-home --shell /usr/sbin/nologin grafana
fi

install_component prometheus "$PROM_VERSION"
install_grafana

old_prometheus_target="$(readlink -f "$INSTALL_ROOT/prometheus" 2>/dev/null || true)"
old_grafana_target="$(readlink -f "$INSTALL_ROOT/grafana" 2>/dev/null || true)"
old_alertmanager_target="$(readlink -f "$INSTALL_ROOT/alertmanager" 2>/dev/null || true)"
systemctl is-active --quiet arxium-prometheus && prometheus_was_active=1
systemctl is-active --quiet arxium-grafana && grafana_was_active=1
systemctl is-active --quiet arxium-alertmanager && alertmanager_was_active=1
systemctl is-enabled --quiet arxium-prometheus && prometheus_was_enabled=1
systemctl is-enabled --quiet arxium-grafana && grafana_was_enabled=1
systemctl is-enabled --quiet arxium-alertmanager && alertmanager_was_enabled=1
if [[ -d "$CONFIG_ROOT" ]]; then
  config_root_existed=1
  cp -a "$CONFIG_ROOT" "$tmp/config-backup" \
    || die "could not back up the existing monitoring configuration"
  had_config_root=1
fi
for unit in arxium-prometheus arxium-grafana arxium-alertmanager; do
  if [[ -f "/etc/systemd/system/$unit.service" ]]; then
    cp -a "/etc/systemd/system/$unit.service" "$tmp/$unit.service" \
      || die "could not back up $unit.service"
  fi
done
systemctl stop arxium-grafana >/dev/null 2>&1 || true
if [[ -d "$STATE_ROOT/grafana/data" ]]; then
  grafana_data_existed=1
  if ! cp -a "$STATE_ROOT/grafana/data" "$tmp/grafana-data-backup"; then
    [[ $grafana_was_active -eq 1 ]] && systemctl restart arxium-grafana
    die "could not back up the Grafana database"
  fi
  had_grafana_data=1
fi
transaction_active=1

ln -sfn "$INSTALL_ROOT/prometheus-$PROM_VERSION" "$INSTALL_ROOT/prometheus"
ln -sfn "$INSTALL_ROOT/grafana-$GRAFANA_VERSION" "$INSTALL_ROOT/grafana"

mkdir -p "$CONFIG_ROOT" "$STATE_ROOT/prometheus"
install -m 0644 "$CONFIG_SRC/prometheus.yml" "$CONFIG_ROOT/prometheus.yml"
install -m 0644 "$CONFIG_SRC/alerts.yml" "$CONFIG_ROOT/alerts.yml"
if [[ -f "$SCRIPT_DIR/alertmanager.yml.example" ]]; then
  install -m 0644 "$SCRIPT_DIR/alertmanager.yml.example" "$CONFIG_ROOT/alertmanager.yml.example"
fi

mkdir -p \
  "$GRAFANA_CONFIG_ROOT/provisioning/datasources" \
  "$GRAFANA_CONFIG_ROOT/provisioning/dashboards" \
  "$GRAFANA_STATE_ROOT/dashboards" \
  "$GRAFANA_STATE_ROOT/data" \
  "$GRAFANA_STATE_ROOT/logs" \
  "$GRAFANA_STATE_ROOT/plugins"
install -m 0644 "$GRAFANA_SRC/provisioning/datasources/prometheus.yml" \
  "$GRAFANA_CONFIG_ROOT/provisioning/datasources/prometheus.yml"
install -m 0644 "$GRAFANA_SRC/provisioning/dashboards/provider.yml" \
  "$GRAFANA_CONFIG_ROOT/provisioning/dashboards/provider.yml"
install -m 0644 "$GRAFANA_SRC/dashboards/arxium-node.json" \
  "$GRAFANA_STATE_ROOT/dashboards/arxium-node.json"

interactive=0
if { exec 3<>/dev/tty; } 2>/dev/null; then
  interactive=1
fi

if [[ -f "$GRAFANA_INITIALIZED" ]]; then
  [[ -f "$GRAFANA_ADMIN_USER_FILE" && -f "$GRAFANA_PUBLIC_HOST_FILE" ]] \
    || die "Grafana initialization marker exists without account metadata"
  [[ -s "$GRAFANA_STATE_ROOT/data/grafana.db" ]] \
    || die "Grafana initialization marker exists without its database; refusing to expose a fresh default account. Restore $GRAFANA_STATE_ROOT/data or remove the marker only after arranging new bootstrap credentials"
  grafana_admin_user="$(cat "$GRAFANA_ADMIN_USER_FILE")"
  grafana_public_host="$(cat "$GRAFANA_PUBLIC_HOST_FILE")"
else
  systemctl stop arxium-grafana >/dev/null 2>&1 || true
  rm -f "$GRAFANA_BOOTSTRAP_ENV"
  if find "$GRAFANA_STATE_ROOT/data" -mindepth 1 -print -quit | grep -q .; then
    die "Grafana data exists without an initialization marker; refusing to delete it. Restore $GRAFANA_INITIALIZED or back up and remove $GRAFANA_STATE_ROOT/data explicitly"
  fi

  if [[ -n ${GRAFANA_PUBLIC_HOST:-} ]]; then
    grafana_public_host="$GRAFANA_PUBLIC_HOST"
  elif [[ $interactive -eq 1 ]]; then
    for ((attempt = 1; attempt <= GRAFANA_INPUT_ATTEMPTS; attempt++)); do
      read -r -p "Public IP address or DNS name for Grafana: " grafana_public_host <&3 \
        || die "could not read the Grafana public host"
      if valid_ipv4 "$grafana_public_host" || valid_dns_name "$grafana_public_host"; then
        break
      fi
      if (( attempt == GRAFANA_INPUT_ATTEMPTS )); then
        die "Grafana public host must be an IPv4 address or DNS name; no attempts remaining"
      fi
      retry_message "Grafana public host must be an IPv4 address or DNS name" "$attempt"
    done
  else
    die "set GRAFANA_PUBLIC_HOST when installing without an interactive terminal"
  fi
  valid_ipv4 "$grafana_public_host" || valid_dns_name "$grafana_public_host" \
    || die "Grafana public host must be an IPv4 address or DNS name"

  if [[ -n ${GRAFANA_ADMIN_USER:-} ]]; then
    grafana_admin_user="$GRAFANA_ADMIN_USER"
  elif [[ $interactive -eq 1 ]]; then
    for ((attempt = 1; attempt <= GRAFANA_INPUT_ATTEMPTS; attempt++)); do
      read -r -p "Grafana username [admin]: " grafana_admin_user <&3 \
        || die "could not read the Grafana username"
      grafana_admin_user="${grafana_admin_user:-admin}"
      valid_grafana_username "$grafana_admin_user" && break
      if (( attempt == GRAFANA_INPUT_ATTEMPTS )); then
        die "Grafana username may contain only letters, digits, dot, underscore, and hyphen; no attempts remaining"
      fi
      retry_message "Grafana username may contain only letters, digits, dot, underscore, and hyphen" "$attempt"
    done
  else
    die "set GRAFANA_ADMIN_USER when installing without an interactive terminal"
  fi
  valid_grafana_username "$grafana_admin_user" \
    || die "Grafana username may contain only letters, digits, dot, underscore, and hyphen"

  if [[ -n ${GRAFANA_ADMIN_PASSWORD:-} ]]; then
    grafana_admin_password="$GRAFANA_ADMIN_PASSWORD"
    grafana_password_confirm="$GRAFANA_ADMIN_PASSWORD"
  elif [[ $interactive -eq 1 ]]; then
    for ((attempt = 1; attempt <= GRAFANA_INPUT_ATTEMPTS; attempt++)); do
      read -r -s -p "Grafana password (12 characters minimum): " grafana_admin_password <&3 \
        || die "could not read the Grafana password"
      printf '\n' >&2
      read -r -s -p "Confirm Grafana password: " grafana_password_confirm <&3 \
        || die "could not read the Grafana password confirmation"
      printf '\n' >&2
      if validate_grafana_password "$grafana_admin_password" "$grafana_password_confirm"; then
        break
      fi
      unset grafana_admin_password grafana_password_confirm
      if (( attempt == GRAFANA_INPUT_ATTEMPTS )); then
        die "$grafana_password_error; no attempts remaining"
      fi
      retry_message "$grafana_password_error" "$attempt"
    done
  else
    die "set GRAFANA_ADMIN_PASSWORD when installing without an interactive terminal"
  fi
  validate_grafana_password "$grafana_admin_password" "$grafana_password_confirm" \
    || die "$grafana_password_error"

  umask 0077
  cat > "$GRAFANA_BOOTSTRAP_ENV" <<EOF
GF_SECURITY_ADMIN_USER='$grafana_admin_user'
GF_SECURITY_ADMIN_PASSWORD='$grafana_admin_password'
EOF
  bootstrap_pending=1
  unset grafana_password_confirm GRAFANA_ADMIN_PASSWORD
fi

tls_pair_valid=0
if [[ -f "$GRAFANA_CERT" && -f "$GRAFANA_KEY" ]] \
  && openssl x509 -checkend 2592000 -noout -in "$GRAFANA_CERT" >/dev/null 2>&1; then
  cert_public_key="$(openssl x509 -in "$GRAFANA_CERT" -pubkey -noout 2>/dev/null)"
  key_public_key="$(openssl pkey -in "$GRAFANA_KEY" -pubout 2>/dev/null)"
  if [[ -n "$cert_public_key" && "$cert_public_key" == "$key_public_key" ]]; then
    tls_pair_valid=1
  fi
fi

if [[ $tls_pair_valid -eq 0 ]]; then
  if valid_ipv4 "$grafana_public_host"; then
    certificate_san="IP:$grafana_public_host"
  else
    certificate_san="DNS:$grafana_public_host"
  fi
  openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
    -subj "/CN=$grafana_public_host" \
    -addext "subjectAltName=$certificate_san" \
    -keyout "$tmp/grafana.key" \
    -out "$tmp/grafana.crt" >/dev/null 2>&1
  cert_public_key="$(openssl x509 -in "$tmp/grafana.crt" -pubkey -noout)"
  key_public_key="$(openssl pkey -in "$tmp/grafana.key" -pubout)"
  [[ "$cert_public_key" == "$key_public_key" ]] || die "generated Grafana TLS certificate and key do not match"
  install -o root -g grafana -m 0640 "$tmp/grafana.key" "$GRAFANA_KEY.new"
  install -o root -g root -m 0644 "$tmp/grafana.crt" "$GRAFANA_CERT.new"
  mv -f "$GRAFANA_KEY.new" "$GRAFANA_KEY"
  mv -f "$GRAFANA_CERT.new" "$GRAFANA_CERT"
fi
chown root:grafana "$GRAFANA_KEY"
chmod 0640 "$GRAFANA_KEY"
chown root:root "$GRAFANA_CERT"
chmod 0644 "$GRAFANA_CERT"

write_grafana_config() {
  local bind_address="$1"
  cat > "$GRAFANA_CONFIG_ROOT/grafana.ini" <<EOF
[paths]
data = $GRAFANA_STATE_ROOT/data
logs = $GRAFANA_STATE_ROOT/logs
plugins = $GRAFANA_STATE_ROOT/plugins
provisioning = $GRAFANA_CONFIG_ROOT/provisioning

[server]
protocol = https
http_addr = $bind_address
http_port = 3000
domain = $grafana_public_host
enforce_domain = true
root_url = https://$grafana_public_host:3000/
cert_file = $GRAFANA_CERT
cert_key = $GRAFANA_KEY
min_tls_version = TLS1.2

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[security]
cookie_samesite = strict
cookie_secure = true
disable_gravatar = true
strict_transport_security = false

[users]
allow_sign_up = false

[auth.basic]
enabled = true
password_policy = true

[auth.anonymous]
enabled = false

[metrics]
enabled = false
EOF
  chmod 0644 "$GRAFANA_CONFIG_ROOT/grafana.ini"
}

if [[ $bootstrap_pending -eq 1 ]]; then
  write_grafana_config 127.0.0.1
else
  write_grafana_config 0.0.0.0
fi

if [[ ! -f "$GRAFANA_ENV" ]]; then
  secret_key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  umask 0077
  cat > "$GRAFANA_ENV" <<EOF
GF_SECURITY_SECRET_KEY='$secret_key'
ARXIUM_GRAFANA_DASHBOARDS_PATH=$GRAFANA_STATE_ROOT/dashboards
EOF
elif ! grep -q '^ARXIUM_GRAFANA_DASHBOARDS_PATH=' "$GRAFANA_ENV"; then
  printf 'ARXIUM_GRAFANA_DASHBOARDS_PATH=%s/dashboards\n' "$GRAFANA_STATE_ROOT" >> "$GRAFANA_ENV"
fi
chown root:grafana "$GRAFANA_ENV"
chmod 0640 "$GRAFANA_ENV"
if [[ -f "$GRAFANA_BOOTSTRAP_ENV" ]]; then
  chown root:root "$GRAFANA_BOOTSTRAP_ENV"
  chmod 0600 "$GRAFANA_BOOTSTRAP_ENV"
fi
umask 0022
chown -R grafana:grafana "$GRAFANA_STATE_ROOT"

cat > "$CONFIG_ROOT/configure-grafana-firewall.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail

grafana_uid="$(id -u grafana)"
nft list table inet arxium_grafana >/dev/null 2>&1 \
  && nft delete table inet arxium_grafana
nft -f - <<RULES
table inet arxium_grafana {
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept
    meta skuid $grafana_uid ip daddr 127.0.0.1 tcp dport 9090 accept
    meta skuid $grafana_uid ip6 daddr ::1 tcp dport 9090 accept
    meta skuid $grafana_uid reject
  }
}
RULES
SCRIPT
chmod 0755 "$CONFIG_ROOT/configure-grafana-firewall.sh"

if [[ $ALERTMANAGER == 1 ]]; then
  [[ -f "$ALERTMANAGER_CONFIG" ]] || die "ALERTMANAGER=1 requires a configured $ALERTMANAGER_CONFIG"
  ! grep -q 'CONFIGURE_ME' "$ALERTMANAGER_CONFIG" || die "configure an Alertmanager receiver and remove the CONFIGURE_ME marker"
  install_component alertmanager "$AM_VERSION"
  ln -sfn "$INSTALL_ROOT/alertmanager-$AM_VERSION" "$INSTALL_ROOT/alertmanager"
  mkdir -p "$STATE_ROOT/alertmanager"
  if [[ "$(readlink -f "$ALERTMANAGER_CONFIG")" != "$(readlink -f "$CONFIG_ROOT/alertmanager.yml" 2>/dev/null || true)" ]]; then
    install -o root -g prometheus -m 0640 "$ALERTMANAGER_CONFIG" "$CONFIG_ROOT/alertmanager.yml"
  else
    chown root:prometheus "$CONFIG_ROOT/alertmanager.yml"
    chmod 0640 "$CONFIG_ROOT/alertmanager.yml"
  fi
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
else
  systemctl disable --now arxium-alertmanager >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/arxium-alertmanager.service
fi

"$INSTALL_ROOT/prometheus/promtool" check config "$CONFIG_ROOT/prometheus.yml"
chown -R prometheus:prometheus "$STATE_ROOT/prometheus"
if [[ $ALERTMANAGER == 1 ]]; then
  chown -R prometheus:prometheus "$STATE_ROOT/alertmanager"
fi

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

cat > /etc/systemd/system/arxium-grafana.service <<UNIT
[Unit]
Description=Arxium node dashboard (Grafana)
After=network-online.target arxium-prometheus.service
Wants=network-online.target
Requires=arxium-prometheus.service

[Service]
User=grafana
WorkingDirectory=$INSTALL_ROOT/grafana
ExecStartPre=+$CONFIG_ROOT/configure-grafana-firewall.sh
EnvironmentFile=$GRAFANA_ENV
EnvironmentFile=-$GRAFANA_BOOTSTRAP_ENV
ExecStart=$INSTALL_ROOT/grafana/bin/grafana server \
  --homepath=$INSTALL_ROOT/grafana \
  --config=$GRAFANA_CONFIG_ROOT/grafana.ini \
  --packaging=tar
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$GRAFANA_STATE_ROOT

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
if [[ $ALERTMANAGER == 1 ]]; then
  systemctl enable arxium-alertmanager
  systemctl restart arxium-alertmanager
fi
systemctl enable arxium-prometheus
systemctl restart arxium-prometheus
systemctl restart arxium-grafana

attempt=1
while [[ $attempt -le 120 ]]; do
  if curl -fsS http://127.0.0.1:9090/-/ready >/dev/null 2>&1 \
    && curl --resolve "$grafana_public_host:3000:127.0.0.1" \
      --cacert "$GRAFANA_CERT" -fsS "https://$grafana_public_host:3000/api/health" \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done

[[ $attempt -le 120 ]] || {
  systemctl status arxium-prometheus --no-pager >&2 || true
  systemctl status arxium-grafana --no-pager >&2 || true
  die "Prometheus and Grafana did not become ready within 120 seconds"
}

if [[ $bootstrap_pending -eq 1 ]]; then
  umask 0077
  cat > "$tmp/grafana-curl.conf" <<EOF
user = "$grafana_admin_user:$grafana_admin_password"
EOF
  grafana_user_response="$(curl \
    --config "$tmp/grafana-curl.conf" \
    --resolve "$grafana_public_host:3000:127.0.0.1" \
    --cacert "$GRAFANA_CERT" \
    -fsS "https://$grafana_public_host:3000/api/user")"
  grep -Fq "\"login\":\"$grafana_admin_user\"" <<< "$grafana_user_response" \
    || die "Grafana did not authenticate the selected administrator account"

  rm -f "$GRAFANA_BOOTSTRAP_ENV"
  write_grafana_config 0.0.0.0
  systemctl restart arxium-grafana
  attempt=1
  while [[ $attempt -le 60 ]]; do
    if curl --resolve "$grafana_public_host:3000:127.0.0.1" \
      --cacert "$GRAFANA_CERT" -fsS "https://$grafana_public_host:3000/api/health" \
      >/dev/null 2>&1; then
      break
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  [[ $attempt -le 60 ]] || die "Grafana did not restart cleanly after removing bootstrap credentials"

  printf '%s\n' "$grafana_admin_user" > "$tmp/grafana-admin-user"
  printf '%s\n' "$grafana_public_host" > "$tmp/grafana-public-host"
  printf 'initialized\n' > "$tmp/grafana-initialized"
  install -m 0644 "$tmp/grafana-admin-user" "$GRAFANA_ADMIN_USER_FILE"
  install -m 0644 "$tmp/grafana-public-host" "$GRAFANA_PUBLIC_HOST_FILE"
  install -m 0644 "$tmp/grafana-initialized" "$GRAFANA_INITIALIZED"
  unset grafana_admin_password grafana_user_response
  bootstrap_pending=0
fi

systemctl enable arxium-grafana
transaction_active=0

certificate_fingerprint="$(openssl x509 -in "$GRAFANA_CERT" -noout -fingerprint -sha256 | cut -d= -f2)"
log "Prometheus is ready at http://127.0.0.1:9090"
log "Grafana is ready at https://$grafana_public_host:3000"
log "Grafana username: $grafana_admin_user"
log "Grafana password: configured and stored by Grafana as a salted hash (not displayed)"
log "Grafana TLS certificate SHA-256 fingerprint: $certificate_fingerprint"
log "If the public URL is unreachable, allow inbound TCP 3000 in the host and provider firewalls."
