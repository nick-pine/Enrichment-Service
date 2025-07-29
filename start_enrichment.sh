#!/bin/bash
# Enrichment Service Quick Deploy Script (Linux)

set -e

# Install dependencies
pip install -r requirements.txt

# Copy environment file if needed
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Copied .env.example to .env. Please edit .env with your settings."
fi

# Run auto setup
python enrichment_service.py auto

# Start the service
python enrichment_service.py start
