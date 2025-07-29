"""
AlertEnrichmentService class for LLM Alert Enrichment Service
"""
import os
import sys
import signal
import logging
import time
import requests
from pathlib import Path
from typing import Dict, Any
from src.core.logger import log
from src.core.alert_filter import AlertFilter
from src.core.wazuh_indexer import WazuhIndexerClient
from src.providers.ollama import query_ollama
from src.config.settings import Settings

class AlertEnrichmentService:
    """Main service class."""
    def __init__(self):
        if not os.path.exists('.env') and len(sys.argv) == 1:
            self._show_first_run_help()
            sys.exit(0)
        self.settings = Settings()
        log(f"Loaded WAZUH_LOOKBACK_MINUTES: {self.settings.lookback_minutes}", tag="CONFIG")
        self.alert_filter = AlertFilter(self.settings.__dict__)
        self.data_client = WazuhIndexerClient({
            'indexer_url': self.settings.wazuh_indexer_url,
            'username': self.settings.wazuh_indexer_user,
            'password': self.settings.wazuh_indexer_pass,
            'index_pattern': getattr(self.settings, 'wazuh_index_pattern', 'wazuh-alerts-*'),
            'enriched_index': getattr(self.settings, 'wazuh_enriched_index', 'wazuh-enriched-alerts'),
            'store_enriched': getattr(self.settings, 'wazuh_store_enriched', True),
            'poll_interval': int(getattr(self.settings, 'wazuh_poll_interval', 30)),
            'lookback_minutes': self.settings.lookback_minutes,
            'timestamp_field': getattr(self.settings, 'timestamp_field', 'timestamp'),
        })
        self.running = False
        self.processed_count = 0
        self.seen_alerts = set()
        self._setup_logging()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _show_first_run_help(self):
        """Show helpful message for first-time users."""
        print("LLM Alert Enrichment Service")
        print("=" * 50)
        print("Welcome! No configuration found.")
        print("")
        print("Quick setup options:")
        print("")
        print("1. Automatic setup (recommended):")
        print("   python enrichment_service.py auto")
        print("")
        print("2. Interactive setup wizard:")
        print("   python enrichment_service.py setup")
        print("")
        print("3. One-command install (installs dependencies too):")
        if os.name == 'posix':
            print("   chmod +x quick-setup.sh && ./quick-setup.sh")
        else:
            print("   quick-setup.bat")
        print("")
        print("4. Test existing services:")
        print("   python enrichment_service.py test")
        print("")

    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.settings.log_level.upper(), logging.INFO)
        log_path = Path(self.settings.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(self.settings.log_file, encoding='utf-8')
            ]
        )

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logging.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def start(self):
        """Start the alert enrichment service."""
        logging.info("Starting LLM Alert Enrichment Service")
        logging.info(f"Data source: {self.settings.data_source}")
        logging.info(f"LLM provider: {self.settings.llm_provider}")
        logging.info(f"Filter: {self.settings.filter_min_severity}+ severity")
        self.running = True
        while self.running:
            try:
                alerts = self.data_client.fetch_new_alerts()
                processed = 0
                for alert in alerts:
                    alert_id = self._get_alert_id(alert)
                    if alert_id in self.seen_alerts:
                        continue
                    should_enrich, reason = self.alert_filter.should_enrich_alert(alert)
                    if not should_enrich:
                        logging.debug(f"Alert {alert_id} filtered: {reason}")
                        self.seen_alerts.add(alert_id)
                        continue
                    enriched = query_ollama(alert, self.settings.llm_model)
                    if self.settings.wazuh_store_enriched:
                        self.data_client.store_enriched_alert(original_alert=alert, enriched_data=enriched.enrichment.dict())
                    risk_score = enriched.enrichment.risk_score if enriched.enrichment else 0
                    category = enriched.enrichment.alert_category if enriched.enrichment else "Unknown"
                    logging.info(f"Enriched {alert_id}: Risk={risk_score}, Category={category}")
                    self.seen_alerts.add(alert_id)
                    processed += 1
                    self.processed_count += 1
                    if len(self.seen_alerts) > 1000:
                        self.seen_alerts.clear()
                if processed > 0:
                    logging.info(f"Processed {processed} alerts")
                time.sleep(self.settings.poll_interval)
            except KeyboardInterrupt:
                logging.info("Received keyboard interrupt")
                break
            except Exception as e:
                logging.error(f"Error in processing loop: {e}")
                time.sleep(10)

    def _get_alert_id(self, alert: Dict[str, Any]) -> str:
        """Generate alert ID for deduplication."""
        if "id" in alert:
            return str(alert["id"])
        import hashlib
        content = f"{alert.get('@timestamp', '')}-{alert.get('rule', {}).get('id', '')}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def stop(self):
        """Stop the service."""
        logging.info("Stopping service...")
        self.running = False
        logging.info(f"Total alerts processed: {self.processed_count}")

    def test(self):
        """Test configuration and connections."""
        logging.info("Testing configuration...")
        try:
            response = requests.get(f"{self.settings.ollama_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = [m.get("name", "") for m in response.json().get("models", [])]
                if self.settings.llm_model in models:
                    logging.info(f"Ollama model {self.settings.llm_model} available")
                else:
                    logging.error(f"Model {self.settings.llm_model} not found")
                    available_models = ", ".join([m.get("name", "") for m in response.json().get("models", [])])
                    logging.info(f"Available models: {available_models}")
                    return False
            else:
                logging.error(f"Ollama API returned {response.status_code}")
                return False
        except Exception as e:
            logging.error(f"Ollama connection failed: {e}")
            if "localhost" in self.settings.ollama_url or "127.0.0.1" in self.settings.ollama_url:
                logging.info("TIP: If running on VM, ensure Ollama is installed and running: 'sudo systemctl status ollama'")
            return False
        if self.settings.data_source == "indexer":
            try:
                from urllib3 import disable_warnings
                from urllib3.exceptions import InsecureRequestWarning
                disable_warnings(InsecureRequestWarning)
                response = requests.get(
                    self.settings.wazuh_indexer_url,
                    auth=(self.settings.wazuh_indexer_user, self.settings.wazuh_indexer_pass),
                    verify=False,
                    timeout=10
                )
                if response.status_code == 200:
                    cluster_info = response.json()
                    cluster_name = cluster_info.get("cluster_name", "unknown")
                    version = cluster_info.get("version", {}).get("number", "unknown")
                    logging.info(f"Wazuh Indexer accessible: {cluster_name} (v{version})")
                else:
                    logging.error(f"Wazuh Indexer returned {response.status_code}")
                    if response.status_code == 401:
                        logging.info("TIP: Check your admin password in .env file")
                    return False
            except Exception as e:
                logging.error(f"Wazuh Indexer connection failed: {e}")
                if "localhost" in self.settings.wazuh_indexer_url or "127.0.0.1" in self.settings.wazuh_indexer_url:
                    logging.info("TIP: If running on VM, ensure Wazuh Indexer is running: 'sudo systemctl status wazuh-indexer'")
                return False
        logging.info("All tests passed!")
        return True

    def status(self):
        """Show service status."""
        logging.info("Service Status:")
        logging.info(f"   Data source: {self.settings.data_source}")
        logging.info(f"   LLM provider: {self.settings.llm_provider} ({self.settings.llm_model})")
        logging.info(f"   Filter: {self.settings.filter_min_severity}+ severity")
        logging.info(f"   Processed: {self.processed_count} alerts")
