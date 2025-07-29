# Architecture Documentation

## Overview

The LLM Alert Enrichment Service is designed with a modular architecture for maintainability, scalability, and ease of testing. All original functionality is preserved, but the codebase is now organized for clarity and future growth.

## Architecture Diagram

```
enrichment_service.py (Entry Point)
    |
    +-- src/cli/
    |     +-- main.py
    |     +-- setup.py
    |     +-- push_alert.py
    |     +-- install.py
    |
    +-- src/core/
    |     +-- service.py
    |     +-- logger.py
    |     +-- alert_filter.py
    |     +-- wazuh_indexer.py
    |     +-- engine.py
    |     +-- validation.py
    |     +-- io.py
    |     +-- preprocessing.py
    |     +-- yara_integration.py
    |     +-- utils.py
    |     +-- wazuh_alert_schema.py
    |     +-- prompt_template.txt
    |
    +-- src/providers/
    |     +-- ollama.py
    |
    +-- src/schemas/
    |     +-- wazuh_schema.py
    |     +-- __init__.py
    |
    +-- src/config/
          +-- settings.py
```

## Key Components

### Entry Point
- **enrichment_service.py**: Minimal script that delegates all logic to CLI and service modules.

### CLI Modules (src/cli/)
- **main.py**: Argument parsing and command routing.
- **setup.py**: Setup wizard and auto-setup logic.
- **push_alert.py**: Push test alerts for validation.
- **install.py**: System service installation logic.

### Core Service (src/core/)
- **service.py**: Main business logic for alert enrichment.
- **logger.py**: Logging utilities.
- **alert_filter.py**: Filtering logic for alerts.
- **wazuh_indexer.py**: Integration with Wazuh Indexer/OpenSearch.
- **engine.py**: Orchestration and processing engine.
- **validation.py**: Input/output validation.
- **io.py**: File and indexer I/O operations.
- **preprocessing.py**: Data normalization and enrichment helpers.
- **yara_integration.py**: YARA rule support.
- **utils.py**: Miscellaneous utilities.
- **wazuh_alert_schema.py**: Alert schema definitions.
- **prompt_template.txt**: Prompt template for LLM enrichment.

### Providers (src/providers/)
- **ollama.py**: LLM provider integration (Ollama).

### Schemas (src/schemas/)
- **wazuh_schema.py**, **__init__.py**: Pydantic schema definitions for alerts and enrichment.

### Config (src/config/)
- **settings.py**: Centralized configuration management.



