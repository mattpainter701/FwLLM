#!/usr/bin/env sh
set -eu

SERVICE_NAME="${SERVICE_NAME:-llm-firewall}"
SERVICE_USER="${SERVICE_USER:-llmfw}"
SERVICE_GROUP="${SERVICE_GROUP:-llmfw}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/llm-fw}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
ENABLE_SERVICE=1
START_SERVICE=0
FORCE_CONFIG=0

usage() {
  cat <<'USAGE'
Usage: sudo ./install.sh [options]

Options:
  --no-enable      Install files but do not enable the systemd service.
  --no-start       Install files but do not start the service.
  --start          Start or restart the service after installation.
  --force-config   Replace /etc/llm-fw/config.yaml if it already exists.
  -h, --help       Show this help.

Environment overrides:
  SERVICE_NAME     Default: llm-firewall
  SERVICE_USER     Default: llmfw
  SERVICE_GROUP    Default: llmfw
  INSTALL_PREFIX   Default: /usr/local
  CONFIG_DIR       Default: /etc/llm-fw
  SYSTEMD_DIR      Default: /etc/systemd/system
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-enable) ENABLE_SERVICE=0 ;;
    --no-start) START_SERVICE=0 ;;
    --start) START_SERVICE=1 ;;
    --force-config) FORCE_CONFIG=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUNDLE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
BINARY_SRC="$BUNDLE_DIR/bin/llm-firewall"
CONFIG_SRC="$BUNDLE_DIR/config/llm-firewall.yaml"
SERVICE_SRC="$BUNDLE_DIR/systemd/llm-firewall.service"
ENV_SRC="$BUNDLE_DIR/config/llm-firewall.env.example"

if [ ! -f "$BINARY_SRC" ]; then
  echo "missing binary: $BINARY_SRC" >&2
  exit 1
fi
if [ ! -f "$CONFIG_SRC" ]; then
  echo "missing config: $CONFIG_SRC" >&2
  exit 1
fi
if [ ! -f "$SERVICE_SRC" ]; then
  echo "missing systemd unit: $SERVICE_SRC" >&2
  exit 1
fi

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
  groupadd --system "$SERVICE_GROUP"
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  NOLOGIN_SHELL="/usr/sbin/nologin"
  if [ ! -x "$NOLOGIN_SHELL" ] && [ -x /sbin/nologin ]; then
    NOLOGIN_SHELL="/sbin/nologin"
  fi
  useradd --system --gid "$SERVICE_GROUP" --home-dir /nonexistent --shell "$NOLOGIN_SHELL" "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 "$INSTALL_PREFIX/bin"
install -o root -g root -m 0755 "$BINARY_SRC" "$INSTALL_PREFIX/bin/llm-firewall"

install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"

if [ -f "$CONFIG_DIR/config.yaml" ] && [ "$FORCE_CONFIG" -ne 1 ]; then
  install -o root -g "$SERVICE_GROUP" -m 0640 "$CONFIG_SRC" "$CONFIG_DIR/config.yaml.new"
  echo "existing config preserved at $CONFIG_DIR/config.yaml"
  echo "new config written to $CONFIG_DIR/config.yaml.new"
else
  install -o root -g "$SERVICE_GROUP" -m 0640 "$CONFIG_SRC" "$CONFIG_DIR/config.yaml"
fi

if [ ! -f "$CONFIG_DIR/llm-firewall.env" ]; then
  if [ -f "$ENV_SRC" ]; then
    install -o root -g "$SERVICE_GROUP" -m 0640 "$ENV_SRC" "$CONFIG_DIR/llm-firewall.env"
  else
    install -o root -g "$SERVICE_GROUP" -m 0640 /dev/null "$CONFIG_DIR/llm-firewall.env"
  fi
  echo "created $CONFIG_DIR/llm-firewall.env; set the upstream API key before starting production traffic"
fi

install -d -o root -g root -m 0755 "$SYSTEMD_DIR"
install -o root -g root -m 0644 "$SERVICE_SRC" "$SYSTEMD_DIR/$SERVICE_NAME.service"

"$INSTALL_PREFIX/bin/llm-firewall" --config "$CONFIG_DIR/config.yaml" --validate-config

systemctl daemon-reload
if [ "$ENABLE_SERVICE" -eq 1 ]; then
  systemctl enable "$SERVICE_NAME"
fi
if [ "$START_SERVICE" -eq 1 ]; then
  if grep -q "replace-with-secret-manager-value" "$CONFIG_DIR/llm-firewall.env"; then
    echo "$CONFIG_DIR/llm-firewall.env still contains the placeholder secret; refusing to start" >&2
    exit 1
  fi
  systemctl restart "$SERVICE_NAME"
fi

echo "installed $SERVICE_NAME"
echo "binary: $INSTALL_PREFIX/bin/llm-firewall"
echo "config: $CONFIG_DIR/config.yaml"
echo "env: $CONFIG_DIR/llm-firewall.env"
if [ "$START_SERVICE" -ne 1 ]; then
  echo "review config/env, then start with: systemctl start $SERVICE_NAME"
fi
