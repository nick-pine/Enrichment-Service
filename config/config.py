# config.py
import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3:latest")

# Data source configuration
DATA_SOURCE = os.getenv("DATA_SOURCE", "file")  # "file" or "indexer"

def get_data_source():
    """Get the configured data source."""
    return os.getenv("DATA_SOURCE", "file")

# File-based configuration
ALERT_LOG_PATH = os.getenv("ALERT_LOG_PATH", "/var/ossec/logs/alerts/alerts.json")
ENRICHED_OUTPUT_PATH = os.getenv("ENRICHED_OUTPUT_PATH", "llm_enriched_alerts.json")

# Elasticsearch configuration (for output)
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "admin")
ELASTIC_PASS = os.getenv("ELASTIC_PASS", "admin")
ENRICHED_INDEX = os.getenv("ENRICHED_INDEX", "wazuh-enriched-alerts")

def get_wazuh_indexer_config():
    """Get Wazuh Indexer configuration from environment variables."""
    return {
        'indexer_url': os.getenv('WAZUH_INDEXER_URL', 'https://localhost:9200'),
        'username': os.getenv('WAZUH_INDEXER_USER', 'admin'),
        'password': os.getenv('WAZUH_INDEXER_PASS', 'admin'),
        'ca_certs': os.getenv('WAZUH_INDEXER_CA_CERTS'),
        'verify_certs': os.getenv('WAZUH_INDEXER_VERIFY_CERTS', 'false').lower() == 'true',
        'index_pattern': os.getenv('WAZUH_INDEX_PATTERN', 'wazuh-alerts-*'),
        'enriched_index': os.getenv('WAZUH_ENRICHED_INDEX', 'wazuh-alerts-enriched'),
        'poll_interval': int(os.getenv('WAZUH_POLL_INTERVAL', '30')),
        'query_size': int(os.getenv('WAZUH_QUERY_SIZE', '100')),
        'lookback_minutes': int(os.getenv('WAZUH_LOOKBACK_MINUTES', '5')),
        'timestamp_field': os.getenv('WAZUH_TIMESTAMP_FIELD', '@timestamp'),
        'store_enriched': os.getenv('WAZUH_STORE_ENRICHED', 'true').lower() == 'true',
        'enrichment_prefix': os.getenv('WAZUH_ENRICHMENT_PREFIX', 'llm_enrichment')
    }

# Alert filtering configuration
def get_filter_config():
    """Get alert filtering configuration from environment variables."""
    config = {}
    
    # Severity filtering
    min_severity = os.getenv("FILTER_MIN_SEVERITY")
    if min_severity:
        config["min_severity"] = min_severity.lower()
    
    max_severity = os.getenv("FILTER_MAX_SEVERITY")
    if max_severity:
        config["max_severity"] = max_severity.lower()
    
    # List-based filtering
    allowed_severities = os.getenv("FILTER_ALLOWED_SEVERITIES")
    if allowed_severities:
        config["allowed_severities"] = [
            s.strip().lower() for s in allowed_severities.split(",") if s.strip()
        ]
    
    blocked_severities = os.getenv("FILTER_BLOCKED_SEVERITIES")
    if blocked_severities:
        config["blocked_severities"] = [
            s.strip().lower() for s in blocked_severities.split(",") if s.strip()
        ]
    
    # Risk score filtering
    min_risk_score = os.getenv("FILTER_MIN_RISK_SCORE")
    if min_risk_score:
        try:
            config["min_risk_score"] = float(min_risk_score)
        except ValueError:
            pass
    
    max_risk_score = os.getenv("FILTER_MAX_RISK_SCORE")
    if max_risk_score:
        try:
            config["max_risk_score"] = float(max_risk_score)
        except ValueError:
            pass
    
    # Rule filtering
    allowed_rules = os.getenv("FILTER_ALLOWED_RULES")
    if allowed_rules:
        config["allowed_rules"] = [
            s.strip() for s in allowed_rules.split(",") if s.strip()
        ]
    
    blocked_rules = os.getenv("FILTER_BLOCKED_RULES")
    if blocked_rules:
        config["blocked_rules"] = [
            s.strip() for s in blocked_rules.split(",") if s.strip()
        ]
    
    # Source filtering
    allowed_sources = os.getenv("FILTER_ALLOWED_SOURCES")
    if allowed_sources:
        config["allowed_sources"] = [
            s.strip() for s in allowed_sources.split(",") if s.strip()
        ]
    
    blocked_sources = os.getenv("FILTER_BLOCKED_SOURCES")
    if blocked_sources:
        config["blocked_sources"] = [
            s.strip() for s in blocked_sources.split(",") if s.strip()
        ]
    
    return config