# LLM Alert Enrichment Service

A modular Python service for enriching security alerts using LLMs (Ollama), designed for maintainability, scalability, and easy integration with Wazuh Indexer/OpenSearch.

## Features
- Modular architecture for clean code and easy extension
- CLI for setup, testing, status, and alert pushing
- Integration with LLM providers (Ollama)
- Alert filtering, enrichment, and indexing
- Centralized configuration management
- Pydantic schemas for validation


## Quickstart & Deployment

See [QUICKSTART.md](QUICKSTART.md) for step-by-step setup and deployment instructions.

### Systemd Service (Recommended)
- Automated install script sets up user, permissions, dependencies, and systemd unit
- Service runs persistently and logs to `/var/log/llm-enrichment.log`
- To check status: `sudo systemctl status llm-enrichment.service`

### Manual CLI Usage
- Start the service: `python enrichment_service.py start`
- Test configuration: `python enrichment_service.py test`
- View status: `python enrichment_service.py status`
- Run setup wizard: `python enrichment_service.py setup`
- Auto setup: `python enrichment_service.py auto`
- Push test alert: `python enrichment_service.py push-alert --file sample_alert.json`

## Development Notes
- Main entry point is minimal (11 lines)
- All business logic is modularized in `src/`
- No circular imports
- Backwards compatibility maintained

## Testing
- All CLI commands function properly
- Service can start, stop, and process alerts
- Configuration and setup wizards work
- No regression in functionality

