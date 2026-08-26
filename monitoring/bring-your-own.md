# Bring your own monitoring

The default node installation exposes metrics at
`http://127.0.0.1:30333/metrics`. An external scraper can reach that endpoint
without opening a public port by maintaining an SSH tunnel from the monitoring
host:

```sh
ssh -N -L 130033:127.0.0.1:30333 operator@node-host
```

Point Prometheus at the local end of the tunnel:

```yaml
scrape_configs:
  - job_name: arxium-node
    static_configs:
      - targets: ['127.0.0.1:130033']
```

Use `autossh` or a systemd unit to keep the tunnel alive. Copy
`prometheus/alerts.yml` into the existing Prometheus rule directory and import
`grafana/dashboards/arxium-node.json` into Grafana if desired.

If the node uses a non-default `ARXD_RPC_BIND`, verify the actual listener
before assuming metrics are loopback-only. The metrics endpoint is part of the
node RPC server and uses the same bind address.
