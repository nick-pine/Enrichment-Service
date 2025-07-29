"""
Service runner for LLM Alert Enrichment Engine.
Runs the enrichment engine as a background service with proper logging and monitoring.
"""

import sys
import os
import time
import signal
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Optional

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# Import after path setup
from config.config import (
    LLM_MODEL,
    DATA_SOURCE,
    ALERT_LOG_PATH,
    ENRICHED_OUTPUT_PATH,
    LLM_PROVIDER,
    get_wazuh_indexer_config
)
from src.core.enhanced_engine import run_enrichment_loop
from src.core.logger import log

class EnrichmentService:
    """Service wrapper for the enrichment engine."""
    
    def __init__(self):
        self.running = False
        self.engine_thread = None
        self.start_time = None
        self.stats = {
            "alerts_processed": 0,
            "errors": 0,
            "uptime_seconds": 0.0
        }
        
        # Setup service logging
        self.setup_logging()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def setup_logging(self):
        """Setup logging for the service."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Create service logger
        self.logger = logging.getLogger("enrichment_service")
        self.logger.setLevel(logging.INFO)
        
        # File handler
        log_file = log_dir / f"enrichment_service_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.stop()
    
    def start(self):
        """Start the enrichment service."""
        if self.running:
            self.logger.warning("Service is already running")
            return
        
        self.logger.info("=" * 60)
        self.logger.info("🚀 Starting LLM Alert Enrichment Service")
        self.logger.info("=" * 60)
        
        # Validate configuration
        if not self._validate_config():
            self.logger.error("Configuration validation failed")
            return False
        
        # Check dependencies
        if not self._check_dependencies():
            self.logger.error("Dependency check failed")
            return False
        
        self.running = True
        self.start_time = datetime.now(timezone.utc)
        
        # Start engine in separate thread
        self.engine_thread = threading.Thread(
            target=self._run_engine_with_monitoring,
            daemon=True
        )
        self.engine_thread.start()
        
        self.logger.info(f"✅ Service started successfully")
        self.logger.info(f"📋 Configuration:")
        self.logger.info(f"   LLM Provider: {LLM_PROVIDER}")
        self.logger.info(f"   LLM Model: {LLM_MODEL}")
        self.logger.info(f"   Alert Log: {ALERT_LOG_PATH}")
        self.logger.info(f"   Output Path: {ENRICHED_OUTPUT_PATH}")
        
        return True
    
    def _validate_config(self):
        """Validate service configuration."""
        try:
            # Check required environment variables
            required_configs = [
                ('LLM_PROVIDER', LLM_PROVIDER),
                ('LLM_MODEL', LLM_MODEL),
                ('ALERT_LOG_PATH', ALERT_LOG_PATH),
                ('ENRICHED_OUTPUT_PATH', ENRICHED_OUTPUT_PATH)
            ]
            
            for name, value in required_configs:
                if not value:
                    self.logger.error(f"Missing configuration: {name}")
                    return False
            
            # Validate alert log path exists or can be created
            alert_path = Path(ALERT_LOG_PATH)
            if not alert_path.exists():
                self.logger.warning(f"Alert log path does not exist: {ALERT_LOG_PATH}")
                # Try to create parent directories
                alert_path.parent.mkdir(parents=True, exist_ok=True)
                # Create empty file for testing
                alert_path.touch()
                self.logger.info(f"Created alert log file: {ALERT_LOG_PATH}")
            
            # Validate output path can be written
            output_path = Path(ENRICHED_OUTPUT_PATH)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.logger.info("✅ Configuration validation passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return False
    
    def _check_dependencies(self):
        """Check if required dependencies are available."""
        try:
            if LLM_PROVIDER.lower() == "ollama":
                # Check if Ollama is running
                import requests
                response = requests.get("http://localhost:11434/api/tags", timeout=5)
                if response.status_code == 200:
                    models = response.json().get('models', [])
                    available_models = [m['name'] for m in models]
                    
                    # Check if our model is available
                    if not any(LLM_MODEL in model for model in available_models):
                        self.logger.warning(f"Model {LLM_MODEL} not found in Ollama")
                        self.logger.info(f"Available models: {available_models}")
                        self.logger.info(f"Run: ollama pull {LLM_MODEL}")
                        return False
                    else:
                        self.logger.info(f"✅ Ollama running with model: {LLM_MODEL}")
                else:
                    self.logger.error("Ollama not responding properly")
                    return False
            
            # Check data source specific dependencies
            if DATA_SOURCE.lower() == "indexer":
                try:
                    import elasticsearch
                    self.logger.info("✅ Elasticsearch library available for Wazuh Indexer")
                    
                    # Test Wazuh Indexer connection
                    from src.core.wazuh_indexer import WazuhIndexerClient
                    indexer_config = get_wazuh_indexer_config()
                    indexer_client = WazuhIndexerClient(indexer_config)
                    
                    connection_test = indexer_client.test_connection()
                    if connection_test['status'] == 'success':
                        self.logger.info(f"✅ Wazuh Indexer connection: {connection_test['cluster_name']}")
                        self.logger.info(f"   Index pattern: {connection_test['index_pattern']}")
                        self.logger.info(f"   Alerts in last hour: {connection_test['alerts_last_hour']}")
                    else:
                        self.logger.error(f"❌ Wazuh Indexer connection failed: {connection_test['message']}")
                        return False
                        
                except ImportError:
                    self.logger.error("❌ Elasticsearch library not installed")
                    self.logger.error("   Install with: pip install elasticsearch")
                    return False
            else:
                # File-based source
                alert_path = Path(ALERT_LOG_PATH)
                if alert_path.exists():
                    self.logger.info(f"✅ Alert log file exists: {ALERT_LOG_PATH}")
                else:
                    self.logger.info(f"⚠️  Alert log file will be created: {ALERT_LOG_PATH}")
            
            self.logger.info("✅ Dependency check passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Dependency check failed: {e}")
            if LLM_PROVIDER.lower() == "ollama":
                self.logger.error("Make sure Ollama is running: ollama serve")
            return False
    
    def _run_engine_with_monitoring(self):
        """Run the enrichment engine with monitoring and error handling."""
        self.logger.info("🔄 Starting enrichment engine...")
        
        retry_count = 0
        max_retries = 5
        
        while self.running:
            try:
                # Run the main enrichment loop
                run_enrichment_loop()
                
            except KeyboardInterrupt:
                self.logger.info("Engine stopped by user")
                break
                
            except Exception as e:
                retry_count += 1
                self.stats["errors"] += 1
                
                self.logger.error(f"Engine error ({retry_count}/{max_retries}): {e}")
                
                if retry_count >= max_retries:
                    self.logger.error("Maximum retries reached, stopping service")
                    self.running = False
                    break
                
                # Exponential backoff
                sleep_time = min(60, 2 ** retry_count)
                self.logger.info(f"Retrying in {sleep_time} seconds...")
                time.sleep(sleep_time)
            
            else:
                # Reset retry count on successful run
                retry_count = 0
    
    def stop(self):
        """Stop the enrichment service."""
        if not self.running:
            self.logger.warning("Service is not running")
            return
        
        self.logger.info("🛑 Stopping enrichment service...")
        self.running = False
        
        # Wait for engine thread to finish
        if self.engine_thread and self.engine_thread.is_alive():
            self.logger.info("Waiting for engine to stop...")
            self.engine_thread.join(timeout=10)
            
            if self.engine_thread.is_alive():
                self.logger.warning("Engine thread did not stop gracefully")
        
        # Calculate uptime
        if self.start_time:
            uptime = datetime.now(timezone.utc) - self.start_time
            self.stats["uptime_seconds"] = uptime.total_seconds()
        
        self.logger.info("📊 Service Statistics:")
        self.logger.info(f"   Uptime: {self.stats['uptime_seconds']:.1f} seconds")
        self.logger.info(f"   Alerts Processed: {self.stats['alerts_processed']}")
        self.logger.info(f"   Errors: {self.stats['errors']}")
        
        self.logger.info("✅ Service stopped successfully")
    
    def status(self):
        """Get service status information."""
        if not self.running:
            return {
                "status": "stopped",
                "uptime_seconds": 0,
                "stats": self.stats
            }
        
        uptime = 0
        if self.start_time:
            uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        
        return {
            "status": "running",
            "uptime_seconds": uptime,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "stats": self.stats,
            "config": {
                "llm_provider": LLM_PROVIDER,
                "llm_model": LLM_MODEL,
                "alert_log_path": ALERT_LOG_PATH,
                "output_path": ENRICHED_OUTPUT_PATH
            }
        }

def main():
    """Main service entry point."""
    service = EnrichmentService()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "status":
            status = service.status()
            print(json.dumps(status, indent=2))
            return
        elif command == "test":
            print("🧪 Testing service configuration...")
            if service._validate_config() and service._check_dependencies():
                print("✅ Service configuration is valid")
                return 0
            else:
                print("❌ Service configuration has issues")
                return 1
    
    # Default: Start the service
    try:
        if service.start():
            # Keep service running
            while service.running:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    break
        
        service.stop()
        
    except Exception as e:
        print(f"Service error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
