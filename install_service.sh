#!/bin/bash
# Automated installer for LLM Alert Enrichment Service systemd unit
set -e

SERVICE_FILE="llm-enrichment.service"
TARGET_PATH="/etc/systemd/system/$SERVICE_FILE"

# Copy the service file
sudo cp "$SERVICE_FILE" "$TARGET_PATH"

# Ensure wazuh user/group exist
if ! id -u wazuh >/dev/null 2>&1; then
    sudo useradd -m wazuh
fi

# Set ownership of the project directory
sudo chown -R wazuh:wazuh /home/user/Enrichment-Service
sudo chmod o+x /home/user

# Create log files and set permissions
sudo touch /var/log/llm-enrichment.log /var/log/llm-enrichment-error.log
sudo chown wazuh:wazuh /var/log/llm-enrichment.log /var/log/llm-enrichment-error.log

# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable llm-enrichment.service
sudo systemctl restart llm-enrichment.service

# Show status
sudo systemctl status llm-enrichment.service
