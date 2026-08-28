# Arxium node monitoring

Every node exports Prometheus metrics from its RPC listener at `/metrics`.
The standard installer binds RPC to `127.0.0.1:30333`, keeping metrics private
to the node host. If you change `ARXD_RPC_BIND`, the metrics endpoint follows
that bind address and must be protected like every other RPC route.

Choose one of these paths. Docker is optional.

| Path | Installs on the node | Best for |
| --- | --- | --- |
| [Native](#native-recommended) | Prometheus, Grafana, and systemd units | A standalone node without a container runtime |
| [Bring your own](bring-your-own.md) | Nothing | Existing Prometheus, Grafana, or hosted monitoring |
| [Docker Compose](#docker-compose) | Prometheus and Grafana containers | Hosts that already use Docker |

## Native (recommended)

The node installer can install native monitoring at the same time:

```sh
curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh \
  | bash -s -- --with-monitoring
```

The flag downloads a checksum-covered monitoring archive from the same release
tag as the node binary. Prometheus, Grafana, and Alertmanager downloads are
also verified against checksums published by their upstream projects. Native
installation requires `nftables` for Grafana process isolation.

From a repository checkout, install or update monitoring directly:

```sh
sudo ./monitoring/native/install-monitoring.sh
```

Prometheus and Grafana run as separate unprivileged system users. Their data is
stored under `/var/lib/arxium-monitoring`. Prometheus stays private on
`127.0.0.1:9090`. Grafana listens publicly on port 3000 with a generated
self-signed TLS certificate.

During the first installation, the installer asks for:

- the node's public IPv4 address or DNS name;
- a Grafana username;
- a Grafana password entered twice without echoing it.

Interactive host, username, and password validation allows three attempts by
default. Set `GRAFANA_INPUT_ATTEMPTS` to a value from 1 through 10 to change the
limit. Invalid values supplied through environment variables fail immediately
because an unattended installation cannot answer another prompt.

Grafana stores the password as a salted hash in its database. The temporary
bootstrap password file is deleted, and Grafana is restarted without the
password in its process environment. The installer prints the username and
certificate fingerprint, but never prints the password. The generated TLS key
and persistent Grafana encryption key are readable only by root and the Grafana
service account. A dedicated nftables policy prevents the public Grafana process
from reaching the node RPC port or initiating any other outbound connection;
only established client responses and access to Prometheus on
`127.0.0.1:9090` are allowed.

Open `https://NODE_IP_OR_NAME:3000`. A self-signed certificate causes a browser
warning until you trust it. Verify the SHA-256 fingerprint printed by the
installer before accepting it. If the page is unreachable, allow inbound TCP
3000 in both the host firewall and the VPS provider firewall.

Prometheus remains available through an SSH tunnel:

```sh
ssh -N \
  -L 9090:127.0.0.1:9090 \
  operator@node-host
```

Then open `http://127.0.0.1:9090` for Prometheus.

Rerunning the installer upgrades the monitoring binaries and provisioning but
preserves the Grafana account, password hash, encryption key, database,
plugins, dashboards, and Prometheus time-series data. The self-signed
certificate is preserved until it has fewer than 30 days remaining, then it is
rotated and its new fingerprint is printed. Non-interactive first installs must
provide `GRAFANA_PUBLIC_HOST`, `GRAFANA_ADMIN_USER`, and
`GRAFANA_ADMIN_PASSWORD` in the installer environment. Avoid placing the
password in shell history.

### Alert delivery

Prometheus evaluates alert rules without Alertmanager. To deliver alerts,
configure a receiver first:

```sh
cp monitoring/native/alertmanager.yml.example monitoring/native/alertmanager.yml
$EDITOR monitoring/native/alertmanager.yml
sudo ALERTMANAGER=1 ./monitoring/native/install-monitoring.sh
```

For an installation made through `install.sh`, the example is also available
at `/etc/arxium-monitoring/alertmanager.yml.example`. Pass a configured file
explicitly when enabling delivery:

```sh
sudo cp /etc/arxium-monitoring/alertmanager.yml.example /etc/arxium-monitoring/alertmanager.yml
sudoedit /etc/arxium-monitoring/alertmanager.yml
sudo ALERTMANAGER=1 \
  ALERTMANAGER_CONFIG=/etc/arxium-monitoring/alertmanager.yml \
  ./monitoring/native/install-monitoring.sh
```

The installer validates the Alertmanager and Prometheus configurations before
restarting either service. Receiver credentials are stored as mode `0640`,
readable only by root and the monitoring service account.

### Uninstall

```sh
sudo ./monitoring/native/uninstall-monitoring.sh
```

The uninstaller removes the Prometheus, Grafana, and optional Alertmanager
services but preserves binaries, credentials, configuration, dashboards, and
time-series data until you deliberately remove their directories.

## Docker Compose

The container path uses host networking so Prometheus can reach the node's
loopback-only metrics endpoint. Both web interfaces remain on loopback. Set a
Grafana password through the environment rather than storing it in this repo:

```sh
cd monitoring
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 32)"
docker compose -f docker-compose.monitoring.yml up -d
```

Tunnel ports `9090` and `3000` over SSH when needed. Do not publish them
directly to the internet.

## Alerts and dashboard

The shipped rules detect:

- an unavailable node metrics endpoint;
- a tip timestamp more than 120 seconds behind wall-clock time;
- a validator set that cannot reach finality quorum with its registered BLS
  keys;
- rejected blocks and block-production errors;
- a sustained mempool backlog.

The Grafana dashboard under `grafana/dashboards/arxium-node.json` shows tip
height and age, finality capacity, peers, block rates, mempool depth, RPC rate,
and consensus round.
