# Arxium node monitoring

Every node exports Prometheus metrics from its RPC listener at `/metrics`.
The standard installer binds RPC to `127.0.0.1:30333`, keeping metrics private
to the node host. If you change `ARXD_RPC_BIND`, the metrics endpoint follows
that bind address and must be protected like every other RPC route.

Choose one of these paths. Docker is optional.

| Path | Installs on the node | Best for |
| --- | --- | --- |
| [Native](#native-recommended) | Prometheus and a systemd unit | A standalone node without a container runtime |
| [Bring your own](bring-your-own.md) | Nothing | Existing Prometheus, Grafana, or hosted monitoring |
| [Docker Compose](#docker-compose) | Prometheus and Grafana containers | Hosts that already use Docker |

## Native (recommended)

The node installer can install native monitoring at the same time:

```sh
curl -fsSL https://raw.githubusercontent.com/Arxium-Protocol/arxium/main/scripts/install.sh \
  | bash -s -- --with-monitoring
```

The flag downloads monitoring files from the same release tag as the node
binary. Prometheus and Alertmanager downloads are verified against checksums
published by their upstream projects.

From a repository checkout, install or update monitoring directly:

```sh
sudo ./monitoring/native/install-monitoring.sh
```

Prometheus runs as an unprivileged system user, stores data under
`/var/lib/arxium-monitoring`, and listens only on `127.0.0.1:9090`. View it
through an SSH tunnel:

```sh
ssh -N -L 9090:127.0.0.1:9090 operator@node-host
```

Then open `http://127.0.0.1:9090` locally.

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

The uninstaller removes services but preserves binaries, configuration, and
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
