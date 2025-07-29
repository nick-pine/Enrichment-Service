"""
Unified configuration management.
"""

import os
from typing import Optional, List
from pathlib import Path
from dotenv import load_dotenv

class Settings:
    """Unified settings class for the application."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize settings from environment and config file."""
        
        # Load environment file if specified
        if config_file and Path(config_file).exists():
            load_dotenv(config_file)
        elif Path(".env").exists():
            load_dotenv(".env")
        
        # Core settings
        self.data_source = os.getenv("DATA_SOURCE", "indexer")
        self.llm_provider = os.getenv("LLM_PROVIDER", "ollama")
        
        # LLM Configuration
        self.llm_model = os.getenv("LLM_MODEL", "llama3:8b")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.ollama_api = os.getenv("OLLAMA_API", f"{self.ollama_url}/api/generate")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        
        # Wazuh Indexer Configuration
        self.wazuh_indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        self.wazuh_indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.wazuh_indexer_pass = os.getenv("WAZUH_INDEXER_PASS", "")
        self.wazuh_index_pattern = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
        self.wazuh_enriched_index = os.getenv("WAZUH_ENRICHED_INDEX", "wazuh-enriched-alerts")
        self.wazuh_store_enriched = self._get_bool("WAZUH_STORE_ENRICHED", True)
        self.timestamp_field = os.getenv("TIMESTAMP_FIELD", "@timestamp")
        
        # File-based configuration (for testing)
        self.alert_log_path = os.getenv("ALERT_LOG_PATH", "sample_alert.json")
        self.enriched_output_path = os.getenv("ENRICHED_OUTPUT_PATH", "enriched_alerts.json")
        
        # Service Configuration
        self.poll_interval = self._get_int("WAZUH_POLL_INTERVAL", 30)
        self.lookback_minutes = self._get_int("WAZUH_LOOKBACK_MINUTES", 5)
        
        # Alert Filtering
        self.filter_min_severity = os.getenv("FILTER_MIN_SEVERITY", "high")
        self.filter_allowed_severities = self._get_list("FILTER_ALLOWED_SEVERITIES", ["high", "critical"])
        self.filter_min_risk_score = self._get_float("FILTER_MIN_RISK_SCORE", 70.0)
        
        # Logging
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = os.getenv("LOG_FILE", "logs/enrichment.log")
        
        # Health Check Configuration
        self.wait_for_llm = self._get_bool("WAIT_FOR_LLM", False)
        self.llm_health_check_interval = self._get_int("LLM_HEALTH_CHECK_INTERVAL", 30)
        self.llm_max_wait_time = self._get_int("LLM_MAX_WAIT_TIME", 300)
    
    def _get_bool(self, key: str, default: bool) -> bool:
        """Get boolean value from environment."""
        value = os.getenv(key, str(default)).lower()
        return value in ("true", "1", "yes", "on")
    
    def _get_int(self, key: str, default: int) -> int:
        """Get integer value from environment."""
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            return default
    
    def _get_float(self, key: str, default: float) -> float:
        """Get float value from environment."""
        try:
            return float(os.getenv(key, str(default)))
        except ValueError:
            return default
    
    def _get_list(self, key: str, default: List[str]) -> List[str]:
        """Get list value from environment (comma-separated)."""
        value = os.getenv(key)
        if value:
            return [item.strip() for item in value.split(",")]
        return default
    
    def get_wazuh_indexer_config(self) -> dict:
        """Get Wazuh Indexer configuration as dict, including advanced fields."""
        return {
            "url": self.wazuh_indexer_url,
            "user": self.wazuh_indexer_user,
            "password": self.wazuh_indexer_pass,
            "index_pattern": self.wazuh_index_pattern,
            "enriched_index": self.wazuh_enriched_index,
            "store_enriched": self.wazuh_store_enriched,
            "lookback_minutes": self.lookback_minutes,
            "timestamp_field": getattr(self, "timestamp_field", "@timestamp"),
            "poll_interval": getattr(self, "poll_interval", 30),
        }
    
    def get_filter_config(self) -> dict:
        """Get alert filter configuration as dict."""
        return {
            "min_severity": self.filter_min_severity,
            "allowed_severities": self.filter_allowed_severities,
            "min_risk_score": self.filter_min_risk_score,
        }
    
    def get_llm_config(self) -> dict:
        """Get LLM configuration as dict."""
        if self.llm_provider == "ollama":
            return {
                "provider": "ollama",
                "model": self.llm_model,
                "url": self.ollama_url,
                "api_endpoint": self.ollama_api,
            }
        elif self.llm_provider == "openai":
            return {
                "provider": "openai",
                "model": self.llm_model,
                "api_key": self.openai_api_key,
            }
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []
        
        # Check required settings
        if self.data_source == "indexer" and not self.wazuh_indexer_pass:
            errors.append("WAZUH_INDEXER_PASS is required for indexer data source")
        
        
        if self.data_source == "file" and not Path(self.alert_log_path).exists():
            errors.append(f"Alert log file not found: {self.alert_log_path}")
        
        # Validate filter settings
        valid_severities = ["low", "medium", "high", "critical"]
        if self.filter_min_severity not in valid_severities:
            errors.append(f"Invalid min_severity: {self.filter_min_severity}")
        
        for severity in self.filter_allowed_severities:
            if severity not in valid_severities:
                errors.append(f"Invalid allowed severity: {severity}")
        
        return errors
    
    def __str__(self) -> str:
        """String representation of settings."""
        return f"Settings(data_source={self.data_source}, llm_provider={self.llm_provider})"
