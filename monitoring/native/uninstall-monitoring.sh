#!/usr/bin/env bash
set -Eeuo pipefail

[[ $(id -u) -eq 0 ]] || { echo "run this uninstaller with sudo" >&2; exit 1; }

systemctl disable --now arxium-prometheus 2>/dev/null || true
systemctl disable --now arxium-alertmanager 2>/dev/null || true
rm -f /etc/systemd/system/arxium-prometheus.service
rm -f /etc/systemd/system/arxium-alertmanager.service
systemctl daemon-reload

echo "Services removed. Data and configuration were preserved:"
echo "  /var/lib/arxium-monitoring"
echo "  /etc/arxium-monitoring"
echo "  /opt/arxium-monitoring"
echo "Remove those directories manually after backing up anything you need."
