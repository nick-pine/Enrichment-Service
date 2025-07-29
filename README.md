# Enrichment Service

A modular Python service for enriching security alerts using LLMs (Ollama, OpenAI, etc.), designed for maintainability, scalability, and easy integration with Wazuh Indexer/OpenSearch.

## Features
- Modular architecture for clean code and easy extension
- CLI for setup, testing, status, and alert pushing
- Integration with LLM providers (Ollama)
- Alert filtering, enrichment, and indexing
- Centralized configuration management
- Pydantic schemas for validation

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   - Copy `.env.example` to `.env` and set your variables as needed.

3. **Run the service:**
   ```bash
   python enrichment_service.py start
   ```

4. **Test configuration:**
   ```bash
   python enrichment_service.py test
   ```

5. **Setup wizard:**
   ```bash
   python enrichment_service.py setup
   ```

6. **Push a test alert:**
   ```bash
   python enrichment_service.py push-alert --file sample_alert.json
   ```

## Usage

- **Start the service:** `python enrichment_service.py start`
- **Test configuration:** `python enrichment_service.py test`
- **View status:** `python enrichment_service.py status`
- **Run setup wizard:** `python enrichment_service.py setup`
- **Auto setup:** `python enrichment_service.py auto`
- **Push test alert:** `python enrichment_service.py push-alert --file sample_alert.json`
- **Install as system service (Linux):** `python enrichment_service.py install-service`

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

