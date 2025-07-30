#!/bin/bash
# Enrichment Service Quick Deploy Script (Linux)

set -e

# Install dependencies
pip install -r requirements.txt

# Ensure correct permissions for systemd service user
SERVICE_USER="wazuh"
PROJECT_DIR="$(pwd)"
sudo chown -R $SERVICE_USER:$SERVICE_USER "$PROJECT_DIR"
sudo chmod o+x /home/user

# Copy environment file if needed
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Copied .env.example to .env. Please edit .env with your settings."
fi

# Prompt for Wazuh Indexer password and update .env
if grep -q '^WAZUH_INDEXER_PASS=' .env; then
    echo -n "Enter Wazuh Indexer password: "
    read WAZUH_INDEXER_PASS
    sed -i "s/^WAZUH_INDEXER_PASS=.*/WAZUH_INDEXER_PASS=$WAZUH_INDEXER_PASS/" .env
fi

# Detect python command
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "Python is not installed."
    exit 1
fi

# Run auto setup
$PYTHON_CMD enrichment_service.py auto

# Start the service
$PYTHON_CMD enrichment_service.py start
