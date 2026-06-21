#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/web_asset_checker}"
DATA_DIR="${DATA_DIR:-/var/lib/web-asset-console}"
CONFIG_DIR="${CONFIG_DIR:-/etc/web-asset-console}"
SERVER_IP="${SERVER_IP:-$(hostname -I | awk '{print $1}')}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "必须使用 root 执行" >&2
  exit 1
fi

id webasset >/dev/null 2>&1 || useradd --system --home-dir "${DATA_DIR}" --shell /usr/sbin/nologin webasset
install -d -o webasset -g webasset -m 0750 "${DATA_DIR}" "${DATA_DIR}/tasks"
install -d -o root -g root -m 0755 "${CONFIG_DIR}"

if [[ ! -f "${DATA_DIR}/paths.txt" ]]; then
  install -o webasset -g webasset -m 0640 "${APP_DIR}/paths.txt" "${DATA_DIR}/paths.txt"
fi

if [[ ! -f "${CONFIG_DIR}/tls.key" || ! -f "${CONFIG_DIR}/tls.crt" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -keyout "${CONFIG_DIR}/tls.key" -out "${CONFIG_DIR}/tls.crt" \
    -subj "/CN=${SERVER_IP}" -addext "subjectAltName=IP:${SERVER_IP}"
  chmod 600 "${CONFIG_DIR}/tls.key"
  chmod 644 "${CONFIG_DIR}/tls.crt"
fi

install -o root -g root -m 0644 "${APP_DIR}/deploy/web-asset-console.service" /etc/systemd/system/web-asset-console.service
install -o root -g root -m 0644 "${APP_DIR}/deploy/nginx-web-asset-console.conf" /etc/nginx/sites-available/web-asset-console
ln -sfn /etc/nginx/sites-available/web-asset-console /etc/nginx/sites-enabled/web-asset-console
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
nginx -t
systemctl enable --now nginx web-asset-console
systemctl restart nginx web-asset-console

echo "部署完成：https://${SERVER_IP}/"
