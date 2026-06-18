#!/usr/bin/env sh
set -eu

SERVICE_NAME="${SERVICE_NAME:-llm-firewall}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/llm-fw}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
PURGE=0

usage() {
  cat <<'USAGE'
Usage: sudo ./uninstall.sh [options]

Options:
  --purge       Remove /etc/llm-fw after uninstalling the service.
  -h, --help    Show this help.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
fi

rm -f "$SYSTEMD_DIR/$SERVICE_NAME.service"
rm -f "$INSTALL_PREFIX/bin/llm-firewall"

if [ "$PURGE" -eq 1 ]; then
  rm -rf "$CONFIG_DIR"
else
  echo "preserved config directory: $CONFIG_DIR"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

echo "uninstalled $SERVICE_NAME"
