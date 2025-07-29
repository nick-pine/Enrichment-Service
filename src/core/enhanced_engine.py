"""
Enhanced enrichment engine that supports both file and Wazuh Indexer data sources.
"""

import json
import time
from datetime import datetime, timezone
from typing import Iterator, Dict, Any

from config.config import (
    LLM_MODEL,
    DATA_SOURCE,
    ALERT_LOG_PATH,
    ENRICHED_OUTPUT_PATH,
    get_filter_config,
    get_wazuh_indexer_config,
    get_data_source
)
from src.providers.ollama import query_ollama
from src.core.llm_health import LLMHealthChecker, get_llm_health_config
from src.core.validation import validate_input_alert, validate_enriched_output
from src.core.io import read_alert_log, write_enriched_output, push_to_elasticsearch
from src.core.logger import log
from src.core.preprocessing import fill_missing_fields, normalize_alert_types
from src.core.alert_filter import AlertFilter

def get_alert_source() -> Iterator[Dict[str, Any]]:
    """Get alert source based on configuration."""
    if DATA_SOURCE.lower() == "indexer":
        log("Using Wazuh Indexer as data source", tag="*")
        return get_indexer_alerts()
    else:
        log("Using file monitoring as data source", tag="*")
        return get_file_alerts()

def get_file_alerts() -> Iterator[Dict[str, Any]]:
    """Get alerts from log file (original implementation)."""
    seen = set()
    
    with read_alert_log(ALERT_LOG_PATH) as logfile:
        while True:
            line = logfile.readline()
            if not line:
                time.sleep(1)
                continue

            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                alert = json.loads(line)
                alert_id = alert.get("id") or f"{alert.get('timestamp')}_{alert.get('rule', {}).get('id')}"
                
                if alert_id in seen:
                    continue
                    
                seen.add(alert_id)
                yield alert
                
            except json.JSONDecodeError as e:
                log(f"Invalid JSON in log file: {e}", tag="!")
                continue
            except Exception as e:
                log(f"Error processing file alert: {e}", tag="!")
                continue

def get_indexer_alerts() -> Iterator[Dict[str, Any]]:
    """Get alerts from Wazuh Indexer."""
    try:
        from src.core.wazuh_indexer import WazuhIndexerClient
        
        indexer_config = get_wazuh_indexer_config()
        indexer_client = WazuhIndexerClient(indexer_config)
        
        # Test connection first
        connection_test = indexer_client.test_connection()
        if connection_test['status'] != 'success':
            log(f"Indexer connection failed: {connection_test['message']}", tag="!")
            return
        
        log(f"Connected to {connection_test['cluster_name']}", tag="INDEXER")
        log(f"Found {connection_test['alerts_last_hour']} alerts in last hour", tag="INDEXER")
        
        # Start polling for alerts
        for alert in indexer_client.poll_alerts():
            yield alert
            
    except ImportError:
        log("Elasticsearch library not available. Install with: pip install elasticsearch", tag="!")
        return
    except Exception as e:
        log(f"Error with Wazuh Indexer: {e}", tag="!")
        return

def run_enrichment_loop():
    """
    Main enrichment loop that works with both file and indexer sources.
    """
    # Initialize alert filter
    filter_config = get_filter_config()
    alert_filter = AlertFilter(filter_config)
    
    # Initialize LLM health checker
    health_config = get_llm_health_config()
    health_checker = LLMHealthChecker(health_config)
    
    # Initialize indexer client for storing enriched alerts (if configured)
    indexer_client = None
    data_source = get_data_source()
    
    if data_source == "indexer":
        try:
            from src.core.wazuh_indexer import WazuhIndexerClient
            indexer_config = get_wazuh_indexer_config()
            indexer_client = WazuhIndexerClient(indexer_config)
            
            # Create enriched index if it doesn't exist
            indexer_client.create_enriched_index()
            log("Initialized Wazuh Indexer for storing enriched alerts", tag="INDEXER")
        except Exception as e:
            log(f"Failed to initialize indexer for storage: {e}", tag="!")
            indexer_client = None
    
    log(f"Starting enrichment with {LLM_MODEL}", tag="*")
    log(f"Data source: {DATA_SOURCE}", tag="*")
    log(f"Filter config: {alert_filter.get_filter_stats()}", tag="FILTER")
    log(f"Wait for LLM: {health_config.get('wait_for_llm', False)}", tag="HEALTH")
    
    # Wait for LLM to be available if configured
    if health_config.get('wait_for_llm', False):
        log("🔍 Wait-for-LLM mode enabled", tag="HEALTH")
        if not health_checker.wait_for_llm_available():
            log("⚠️ Proceeding with degraded mode after wait timeout", tag="HEALTH")
        else:
            log("✅ LLM is ready, starting enrichment", tag="HEALTH")
    
    try:
        for alert in get_alert_source():
            try:
                # Preprocess alert
                alert = fill_missing_fields(alert)
                alert = normalize_alert_types(alert)
                
                # Generate alert ID
                alert_id = alert.get("id") or f"{alert.get('timestamp')}_{alert.get('rule', {}).get('id')}"
                
                # Check if alert should be enriched
                should_enrich, filter_reason = alert_filter.should_enrich_alert(alert)
                if not should_enrich:
                    log(f"Skipping alert {alert_id}: {filter_reason}", tag="FILTER")
                    continue

                # Validate alert
                try:
                    validate_input_alert(alert)
                except Exception as validation_error:
                    log(f"Alert validation failed for {alert_id}: {validation_error}", tag="!")
                    continue

                log(f"Enriching alert {alert_id}...", tag="+")
                
                # Check LLM health before processing (if wait mode enabled)
                if health_config.get('wait_for_llm', False):
                    if not health_checker.is_llm_healthy():
                        log(f"🔄 LLM not healthy, waiting for recovery before processing {alert_id}...", tag="HEALTH")
                        if not health_checker.wait_for_llm_available():
                            log(f"⚠️ LLM still unavailable, skipping alert {alert_id}", tag="HEALTH")
                            continue
                
                # Enrich with LLM
                enriched = None
                try:
                    enriched = query_ollama(alert, model=LLM_MODEL)
                except Exception as e:
                    if health_config.get('wait_for_llm', False):
                        log(f"🔄 LLM failed during enrichment for {alert_id}, will retry after recovery", tag="HEALTH")
                        # In wait mode, mark LLM as unhealthy and retry
                        health_checker._last_health_status = False
                        continue
                    else:
                        log(f"LLM provider failed for {alert_id}: {e}", tag="!")

                # Prepare enrichment data
                enrichment_data = None
                if enriched and hasattr(enriched, "enrichment"):
                    enrichment_data = enriched.enrichment.model_dump()
                    # Ensure yara_matches is always present
                    if "yara_matches" not in enrichment_data or enrichment_data["yara_matches"] is None:
                        enrichment_data["yara_matches"] = []
                else:
                    enrichment_data = {
                        "summary_text": None,
                        "tags": [],
                        "risk_score": None,
                        "false_positive_likelihood": None,
                        "alert_category": None,
                        "remediation_steps": [],
                        "related_cves": [],
                        "external_refs": [],
                        "llm_model_version": None,
                        "enriched_by": None,
                        "enrichment_duration_ms": None,
                        "yara_matches": [],
                        "raw_llm_response": None,
                        "error": "Validation or enrichment failed"
                    }

                # Create output document
                output = {
                    "alert_id": alert_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert": alert,
                    "enrichment": enrichment_data
                }

                # Validate output
                try:
                    validate_enriched_output(output)
                except Exception as e:
                    log(f"Output validation failed for {alert_id}: {e}", tag="!")
                    # Continue anyway for debugging

                # Write output
                write_enriched_output(ENRICHED_OUTPUT_PATH, output)
                push_to_elasticsearch(output)
                
                # Store enriched alert back to Wazuh Indexer (if configured)
                if indexer_client and indexer_client.store_enriched:
                    try:
                        stored = indexer_client.store_enriched_alert(alert, enrichment_data)
                        if stored:
                            log(f"Stored enriched alert {alert_id} to Wazuh Indexer", tag="✓")
                        else:
                            log(f"Failed to store enriched alert {alert_id} to indexer", tag="!")
                    except Exception as e:
                        log(f"Error storing to Wazuh Indexer: {e}", tag="!")
                
                log(f"Successfully enriched alert {alert_id}", tag="✓")
                
                # Rate limiting
                time.sleep(1.5)
                
            except Exception as e:
                log(f"Error processing alert: {e}", tag="!")
                continue
                
    except KeyboardInterrupt:
        log("Enrichment loop stopped by user", tag="*")
    except Exception as e:
        log(f"Fatal error in enrichment loop: {e}", tag="!")
        raise
