# Linux Install Bundle

This archive installs FwLLM as a systemd service on a Linux VM.

## Contents

```text
bin/llm-firewall
config/llm-firewall.yaml
config/llm-firewall.env.example
systemd/llm-firewall.service
install/linux/install.sh
install/linux/uninstall.sh
```

## Install

```bash
tar -xzf fwllm-<version>-linux-x86_64.tar.gz
cd fwllm-<version>-linux-x86_64
sudo sh ./install/linux/install.sh
sudo editor /etc/llm-fw/config.yaml
sudo editor /etc/llm-fw/llm-firewall.env
sudo systemctl start llm-firewall
```

## Validate

```bash
sudo -u llmfw /usr/local/bin/llm-firewall --config /etc/llm-fw/config.yaml --validate-config
curl -sS http://127.0.0.1:8080/healthz
```

## Upgrade

```bash
sudo sh ./install/linux/install.sh --no-start
sudo systemctl restart llm-firewall
```

Existing `/etc/llm-fw/config.yaml` is preserved by default. A new config is written to `/etc/llm-fw/config.yaml.new` unless `--force-config` is used.

## Uninstall

```bash
sudo sh ./install/linux/uninstall.sh
```

Use `--purge` only when the local config and environment file should be removed.
