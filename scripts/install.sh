#!/usr/bin/env bash
# Arxium node installer. Gets an operator from zero to a running `arxd`
# under systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh | bash
#
# To read it first (recommended, and the point of it being one file):
#   curl -fsSL .../install.sh -o install.sh && less install.sh && bash install.sh
#
# What it does NOT do: no daemonizing inside arxd, no PID files, no restart
# logic in the binary. arxd runs in the foreground and logs to stdout;
# systemd owns the lifecycle and journald owns the logs. That split is
# deliberate — see docs/runbook.md.
set -euo pipefail

REPO="Arxium-Protocol/arxium"
ASSET_ARCH="x86_64-linux-gnu"

version=""
base_path="${ARXD_BASE_PATH:-$HOME/.arxium}"
assume_yes=0
dry_run=0
with_monitoring=0

usage() {
    cat <<'USAGE'
Usage: install.sh [options]

  --version vX.Y.Z   Install this release instead of the latest.
  --base-path DIR    Node directory (default: ~/.arxium).
  --dry-run          Print what would happen; touch nothing.
  --with-monitoring  Install native Prometheus and Grafana under systemd.
  --yes              Non-interactive: accept every default, no prompts.
  -h, --help         This text.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2:?--version needs a tag, e.g. v0.1.0}"; shift 2 ;;
        --base-path) base_path="${2:?--base-path needs a directory}"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        --with-monitoring) with_monitoring=1; shift ;;
        --yes|-y) assume_yes=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# In --dry-run every mutating command routes through this, so there is one
# place to audit for "does this actually touch the disk".
run() {
    if [ "$dry_run" -eq 1 ]; then
        printf '  would run: %s\n' "$*"
    else
        "$@"
    fi
}

# Prompt with a default. Honours --yes, and also falls back to the default
# when there's no TTY — which is the `curl | bash` case, where stdin is the
# script itself and reading from it would eat the script.
ask() {
    local prompt="$1" default="$2" reply
    if [ "$assume_yes" -eq 1 ] || [ ! -t 0 ]; then
        printf '%s\n' "$default"
        return
    fi
    read -r -p "$prompt [$default]: " reply </dev/tty || reply=""
    printf '%s\n' "${reply:-$default}"
}

ask_yn() {
    local prompt="$1" default="$2" reply
    reply="$(ask "$prompt (y/n)" "$default")"
    case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------- preflight

for tool in curl tar install; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

# sha256sum on Linux, shasum -a 256 on macOS. Checksum verification is not
# optional, and each downloaded asset must have one exact manifest entry.
if command -v sha256sum >/dev/null 2>&1; then
    sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    die "need sha256sum or shasum to verify the download; refusing to install unverified"
fi

verify_checksum() {
    sums_file=$1
    filename=$2
    expected=$(awk -v filename="$filename" \
        '$2 == filename || $2 == "*" filename { print $1 }' "$sums_file")
    printf '%s\n' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$' \
        || die "SHA256SUMS has no single valid checksum for ${filename}"
    actual=$(sha256_file "$filename")
    [ "$actual" = "$expected" ]
}

os="$(uname -s)"
arch="$(uname -m)"
have_systemd=0
if [ "$os" = "Linux" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    have_systemd=1
fi

if [ "$with_monitoring" -eq 1 ]; then
    [ "$have_systemd" -eq 1 ] || die "--with-monitoring requires Linux with systemd"
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || die "--with-monitoring requires sudo when not run as root"
    fi
fi

# Releases only ship x86_64 Linux today (see .github/workflows/ci.yml).
# Everything else can still have the directory laid out for it, but there is
# no binary to fetch, so say that plainly instead of downloading a 404.
if [ "$os" != "Linux" ] || [ "$arch" != "x86_64" ]; then
    die "no prebuilt binary for ${os}/${arch} — releases are ${ASSET_ARCH} only.
Build from source instead: cargo build --release -p arxd"
fi

# ------------------------------------------------------------ resolve version

if [ -z "$version" ]; then
    say "Resolving the latest release..."
    # Unauthenticated API, 60 requests/hour/IP — plenty for an installer, and
    # it avoids depending on jq being present.
    version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$version" ] || die "could not determine the latest release tag.
The releases API returned nothing usable, which usually means one of:
  - the repository is private, and anonymous requests get a 404. This
    installer does not authenticate; fetch the tarball manually or wait
    until the repository is public.
  - there is no published release yet.
  - the unauthenticated API rate limit (60/hour/IP) is exhausted.
Pass --version vX.Y.Z to skip this lookup entirely."
fi

asset="arxd-${version}-${ASSET_ARCH}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${version}"
say "Installing arxd ${version}"

# ------------------------------------------------------------------- prompts

base_path="$(ask 'Node directory' "$base_path")"
# Expand a leading ~ that came from an interactive answer, where it's a
# literal character rather than something the shell already expanded.
case "$base_path" in "~"/*) base_path="$HOME/${base_path#"~"/}" ;; esac

validator="false"
if ask_yn 'Run this node as a validator?' 'n'; then validator="true"; fi

rpc_bind="$(ask 'RPC bind address (127.0.0.1 = loopback only)' '127.0.0.1')"
rpc_token="$(ask 'RPC bearer token (blank = no auth)' '')"

if [ "$rpc_bind" != "127.0.0.1" ] && [ -z "$rpc_token" ]; then
    warn "RPC is bound to ${rpc_bind} with no token — anyone who can reach the port can submit actions."
fi

# --------------------------------------------------------- download + verify

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Downloading ${asset}"
if [ "$dry_run" -eq 1 ]; then
    printf '  would download: %s/%s\n' "$base_url" "$asset"
    printf '  would download: %s/SHA256SUMS\n' "$base_url"
    printf '  would verify the archive against SHA256SUMS before unpacking\n'
else
    # A 404 here is ambiguous and the ambiguity matters: a private repository
    # returns exactly the same status as a tag that doesn't exist, so naming
    # only one of them sends the operator looking in the wrong place.
    curl -fSL --progress-bar -o "$tmp/$asset" "$base_url/$asset" \
        || die "could not download ${asset}.
GitHub returns 404 for both of these, so check both:
  - the repository is private. Release assets on a private repo cannot be
    fetched anonymously, and this installer does not authenticate. Until it
    is public, copy the tarball across by hand and unpack it into
    <base_path>/bin yourself.
  - ${version} is not a published release tag.
Releases: https://github.com/${REPO}/releases"
    curl -fsSL -o "$tmp/SHA256SUMS" "$base_url/SHA256SUMS" \
        || die "release ${version} has no SHA256SUMS asset; refusing to install unverified.
If the tarball downloaded but this did not, the release was published without
its checksum file — re-run the release workflow rather than skipping this."

    say "Verifying checksum"
    # Verified before the archive is ever unpacked, let alone executed.
    ( cd "$tmp" && verify_checksum SHA256SUMS "$asset" ) \
        || die "checksum mismatch — do not run this binary"

    tar -xzf "$tmp/$asset" -C "$tmp"
    binary="$(find "$tmp" -name arxd -type f | head -1)"
    [ -n "$binary" ] || die "no arxd binary inside ${asset}"
fi

# Fetch the checksum-covered monitoring archive from the same immutable release
# as the node binary. Downloading and verifying it before laying out the node
# keeps an unavailable or incomplete bundle from leaving a partial install.
monitoring_dir="$tmp/monitoring"
if [ "$with_monitoring" -eq 1 ]; then
    monitoring_asset="arxium-monitoring-${version}.tar.gz"
    say "Downloading the ${version} monitoring bundle"
    if [ "$dry_run" -eq 1 ]; then
        printf '  would download: %s/%s\n' "$base_url" "$monitoring_asset"
        printf '  would verify the monitoring archive against SHA256SUMS before unpacking\n'
    else
        curl -fSL --progress-bar -o "$tmp/$monitoring_asset" \
            "$base_url/$monitoring_asset" \
            || die "release ${version} has no monitoring archive"
        ( cd "$tmp" && verify_checksum SHA256SUMS "$monitoring_asset" ) \
            || die "monitoring checksum mismatch — do not execute the installer"
        tar -xzf "$tmp/$monitoring_asset" -C "$tmp"
        [ -x "$monitoring_dir/native/install-monitoring.sh" ] \
            || die "monitoring archive does not contain the native installer"
    fi
fi

# --------------------------------------------------------------- lay out dirs

say "Creating ${base_path}"
for dir in bin configs; do
    run mkdir -p "$base_path/$dir"
done
# validator.key/network.key land directly in base_path (shared across every
# chain this node runs); each chain gets its own <base_path>/<chain-name> data
# dir (e.g. corechain/), created by arxd itself on first run. Nothing but arxd
# should read base_path; scripts/backup-node.sh is what gets it off-box.
run chmod 700 "$base_path"

say "Installing binary to ${base_path}/bin/arxd"
if [ "$dry_run" -eq 1 ]; then
    printf '  would install the unpacked arxd to %s/bin/arxd\n' "$base_path"
else
    install -m 0755 "$binary" "$base_path/bin/arxd"
fi

# ------------------------------------------------------------------ env file

# Config lives in an env file rather than a TOML file because systemd reads
# it natively via EnvironmentFile= and clap reads it natively via `env =`
# on RunArgs — so there's no config parser, no precedence rules, and no new
# dependency in arxd. Every key is written with an explicit value, including
# the false ones; `--validator false` works because those args are
# ArgAction::Set (see core/cli's bool_env_vars_need_an_explicit_value test).
env_file="$base_path/configs/arxd.env"
say "Writing ${env_file}"
if [ "$dry_run" -eq 1 ]; then
    printf '  would write the env file (ARXD_VALIDATOR=%s, ARXD_RPC_BIND=%s)\n' "$validator" "$rpc_bind"
elif [ -f "$env_file" ]; then
    warn "${env_file} already exists — keeping it. Delete it and re-run to regenerate."
else
    cat > "$env_file" <<ENVFILE
# arxd configuration. Read by systemd (EnvironmentFile=) and by arxd itself
# (clap \`env\` on RunArgs). A command-line flag overrides anything here, so
# you can test a change with a one-off run before editing this file.
#
# Apply changes with: systemctl restart arxd

ARXD_BASE_PATH=$base_path
ARXD_CHAIN=devnet
ARXD_VALIDATOR=$validator
ARXD_PORT=30333
ARXD_P2P_PORT=30334

# Loopback-only by default. Put a TLS-terminating reverse proxy in front
# before changing this — arxd speaks plain HTTP.
ARXD_RPC_BIND=$rpc_bind

# Blank means no auth. Generate one with: openssl rand -hex 32
ARXD_RPC_TOKEN=$rpc_token

# Comma-separated peer multiaddrs. Blank falls back to the chain spec's
# own boot_nodes list, which is the right answer for devnet.
ARXD_BOOTNODES=

# DEVNET ONLY, and exactly one node per network may set this true.
ARXD_BOOTNODE=false
ENVFILE
    # The token lives in here.
    chmod 600 "$env_file"
fi

# ------------------------------------------------------------ validator key

# Generated before the service starts so the operator sees the address now,
# rather than discovering after an hour of silence that this node was never
# in the validator set. This is the single most common way a node fails
# silently — see docs/runbook.md.
if [ "$dry_run" -eq 0 ]; then
    say "Node validator address"
    address="$("$base_path/bin/arxd" validator-key --base-path "$base_path")"
    printf '\n    %s\n\n' "$address"
    if [ "$validator" = "true" ]; then
        echo "  This address must be in the chain spec's validator set, or be added"
        echo "  via a JoinValidator action, before this node can produce a block."
        echo "  Until then it runs, syncs, serves RPC — and never proposes."
        echo
    fi
fi

# ------------------------------------------------------------------- systemd

service_file="/etc/systemd/system/arxd.service"
service_installed=0

if [ "$have_systemd" -eq 0 ]; then
    warn "no systemd here — skipping service installation."
    echo "  Run the node in the foreground with:"
    echo "    set -a; . $env_file; set +a; $base_path/bin/arxd"
else
    # Generated before the prompt, not inside the yes branch: if the operator
    # declines, the unit is still worth keeping (it already has this node's
    # real paths baked in) and $tmp is wiped by the EXIT trap moments later.
    unit="$tmp/arxd.service"
    cat > "$unit" <<UNIT
[Unit]
Description=Arxium node (arxd)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(id -un)
WorkingDirectory=$base_path
EnvironmentFile=$env_file
ExecStart=$base_path/bin/arxd
# arxd runs in the foreground and logs to stdout; journald captures it.
# Read with: journalctl -u arxd -f
Restart=always
RestartSec=5
# NOTE: a restart does NOT recover a chain that has stopped producing
# blocks — the process stays healthy through a stall. Alert on the tip
# advancing, not on this unit being active.

# Hardening. arxd needs its base path and the network, nothing else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$base_path

[Install]
WantedBy=multi-user.target
UNIT

    if ask_yn "Install the systemd service (needs sudo, writes ${service_file})?" 'y'; then
        say "Installing ${service_file}"
        if [ "$dry_run" -eq 1 ]; then
            printf '  would sudo install -m 0644 the unit to %s\n' "$service_file"
            printf '  would run: sudo systemctl daemon-reload\n'
        else
            sudo install -m 0644 "$unit" "$service_file"
            sudo systemctl daemon-reload
        fi
        service_installed=1

        if ask_yn 'Start arxd on boot?' 'y'; then
            run sudo systemctl enable arxd
        fi
        if ask_yn 'Start arxd now?' 'y'; then
            run sudo systemctl start arxd
        fi
    else
        kept_unit="$base_path/configs/arxd.service"
        say "Skipped installing the service."
        if [ "$dry_run" -eq 1 ]; then
            printf '  would keep the generated unit at %s\n' "$kept_unit"
        else
            cp "$unit" "$kept_unit"
            echo "  Generated unit kept at ${kept_unit} — install it later with:"
            echo "    sudo install -m 0644 ${kept_unit} ${service_file} && sudo systemctl daemon-reload"
        fi
        echo "  Or run in the foreground now:"
        echo "    set -a; . $env_file; set +a; $base_path/bin/arxd"
    fi
fi

# --------------------------------------------------------------- monitoring

if [ "$with_monitoring" -eq 1 ]; then
    say "Installing native node monitoring"
    if [ "$dry_run" -eq 1 ]; then
        printf '  would run the release-matched monitoring installer with root privileges\n'
    elif [ "$(id -u)" -eq 0 ]; then
        bash "$monitoring_dir/native/install-monitoring.sh"
    else
        sudo --preserve-env=GRAFANA_PUBLIC_HOST,GRAFANA_ADMIN_USER,GRAFANA_ADMIN_PASSWORD,GRAFANA_INPUT_ATTEMPTS,ALERTMANAGER,ALERTMANAGER_CONFIG \
            bash "$monitoring_dir/native/install-monitoring.sh"
    fi
fi

# ---------------------------------------------------------------------- done

cat <<DONE

$(say 'Done.')

  Binary   $base_path/bin/arxd
  Config   $env_file
  Keys     $base_path/*.key
  Data     $base_path/corechain/data
  Snapshot $base_path/corechain/snapshots

$(if [ "$service_installed" -eq 1 ]; then cat <<'SYSTEMD'
  Logs     journalctl -u arxd -f
  Status   systemctl status arxd
  Restart  systemctl restart arxd
SYSTEMD
else
    printf '  Service  not installed — see above for how to start the node\n'
fi)
  Health   curl -s localhost:30333/status

  Back up $base_path — validator.key has no recovery path if lost.
  scripts/backup-node.sh does this; run it from cron and copy the
  tarballs off-box.
DONE
