"""
Wazuh Indexer integration for the LLM enrichment engine.
Pulls alerts directly from Wazuh Indexer (OpenSearch) instead of log files.
"""

import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Generator
from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError, RequestError
from src.core.logger import log

class WazuhIndexerClient:
    """Client for reading alerts from Wazuh Indexer."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Wazuh Indexer client."""
        self.config = config
        self.es_client: Optional[OpenSearch] = None
        self.last_timestamp: Optional[datetime] = None
        self.seen_alerts = set()
        
        # Configuration
        self.indexer_url = config.get('indexer_url', 'https://localhost:9200')
        self.username = config.get('username', 'admin')
        self.password = config.get('password', 'admin')
        self.ca_certs = config.get('ca_certs')
        self.verify_certs = config.get('verify_certs', False)

        # Index configuration
        self.index_pattern = config.get('index_pattern', 'wazuh-alerts-*')
        self.enriched_index = config.get('enriched_index', 'wazuh-enriched-alerts')
        self.query_size = config.get('query_size', 100)
        self.poll_interval = config.get('poll_interval', 30)  # seconds
        self.lookback_minutes = int(config.get('lookback_minutes', 5))

        # Filtering
        self.timestamp_field = config.get('timestamp_field', '@timestamp')
        self.custom_query = config.get('custom_query', {})

        # Enrichment settings
        self.store_enriched = config.get('store_enriched', True)
        self.enrichment_prefix = config.get('enrichment_prefix', 'llm_enrichment')

        # Always initialize last_timestamp to lookback window
        self.last_timestamp = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
        log(f"Initialized last_timestamp to {self.last_timestamp.isoformat()} (lookback {self.lookback_minutes} min)", tag="INDEXER")

        self._connect()
    
    def _connect(self):
        """Establish connection to Wazuh Indexer."""
        try:
            es_config = {
                'hosts': [self.indexer_url],
                'http_auth': (self.username, self.password),
                'verify_certs': self.verify_certs,
                'ssl_assert_hostname': False,
                'ssl_show_warn': False
            }
            
            if self.ca_certs:
                es_config['ca_certs'] = self.ca_certs
                es_config['verify_certs'] = True
                log(f"Using CA certs: {self.ca_certs}", tag="INDEXER")
            else:
                if not self.verify_certs:
                    log("SSL verification disabled (not recommended for production)", tag="INDEXER")
            
            # Initialize OpenSearch client
            self.es_client = OpenSearch(**es_config)
            
            # Test connection
            info = self.es_client.info()
            log(f"Connected to Wazuh Indexer: {info['cluster_name']} v{info['version']['number']}", tag="INDEXER")
            
            # last_timestamp is already initialized in __init__ with correct lookback value
            
            return True
            
        except Exception as e:
            log(f"Failed to connect to Wazuh Indexer: {e}", tag="INDEXER")
            return False
    
    def _build_query(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Build Elasticsearch query for fetching alerts."""
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            self.timestamp_field: {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        # Add custom query filters if specified
        if self.custom_query:
            if "must" in self.custom_query:
                query["bool"]["must"].extend(self.custom_query["must"])
            if "must_not" in self.custom_query:
                query["bool"]["must_not"] = self.custom_query["must_not"]
            if "should" in self.custom_query:
                query["bool"]["should"] = self.custom_query["should"]
                query["bool"]["minimum_should_match"] = self.custom_query.get("minimum_should_match", 1)
        
        return {
            "query": query,
            "sort": [
                {self.timestamp_field: {"order": "asc"}}
            ],
            "size": self.query_size
        }
    
    def fetch_new_alerts(self) -> Generator[Dict[str, Any], None, None]:
        """Fetch new alerts from Wazuh Indexer since last check."""
        if not self.es_client:
            if not self._connect():
                return
        
        if not self.es_client or not self.last_timestamp:
            return
        
        try:
            end_time = datetime.now(timezone.utc)
            start_time = self.last_timestamp
            log(f"Querying alerts from {start_time.isoformat()} to {end_time.isoformat()}", tag="INDEXER")
            search_body = self._build_query(start_time, end_time)
            log(f"Search body: {search_body}", tag="INDEXER")
            # Use scroll for large result sets
            response = self.es_client.search(
                index=self.index_pattern,
                body=search_body
            )
            
            total_hits = response['hits']['total']['value']
            log(f"Found {total_hits} alerts in time range", tag="INDEXER")
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            
            alert_count = 0
            new_alerts = 0
            
            while hits:
                for hit in hits:
                    alert_count += 1
                    
                    # Extract alert data
                    alert = hit['_source']
                    alert_id = hit.get('_id', alert.get('id', f"alert_{alert_count}"))
                    
                    # Check for duplicates
                    if alert_id in self.seen_alerts:
                        continue
                    
                    self.seen_alerts.add(alert_id)
                    new_alerts += 1
                    
                    # Update timestamp for next query
                    alert_timestamp = alert.get(self.timestamp_field)
                    if alert_timestamp:
                        try:
                            parsed_time = datetime.fromisoformat(alert_timestamp.replace('Z', '+00:00'))
                            if parsed_time.tzinfo is None:
                                # Make timezone-aware (UTC)
                                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
                            if parsed_time > self.last_timestamp:
                                self.last_timestamp = parsed_time
                        except ValueError:
                            pass
                    
                    # Add metadata
                    alert['_indexer_metadata'] = {
                        'index': hit['_index'],
                        'id': hit['_id'],
                        'score': hit.get('_score'),
                        'fetched_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    yield alert
                
                # Get next batch
                if scroll_id:
                    try:
                        response = self.es_client.scroll(scroll_id=scroll_id)
                        hits = response['hits']['hits']
                    except Exception as e:
                        log(f"Scroll error: {e}", tag="INDEXER")
                        break
                else:
                    break
            
            log(f"Processed {alert_count} alerts, {new_alerts} new", tag="INDEXER")
            
            # Clear scroll
            if scroll_id:
                try:
                    self.es_client.clear_scroll(scroll_id=scroll_id)
                except Exception:
                    pass
                    
        except ConnectionError as e:
            log(f"Connection error to Wazuh Indexer: {e}", tag="INDEXER")
            self.es_client = None  # Force reconnection next time
            
        except RequestError as e:
            log(f"Query error: {e}", tag="INDEXER")
            
        except Exception as e:
            log(f"Unexpected error fetching alerts: {e}", tag="INDEXER")
    
    def poll_alerts(self) -> Generator[Dict[str, Any], None, None]:
        """Continuously poll for new alerts."""
        log(f"Starting continuous polling (interval: {self.poll_interval}s)", tag="INDEXER")
        
        while True:
            try:
                alert_yielded = False
                for alert in self.fetch_new_alerts():
                    alert_yielded = True
                    yield alert
                
                if not alert_yielded:
                    log(f"No new alerts, sleeping {self.poll_interval}s", tag="INDEXER")
                
                time.sleep(self.poll_interval)
                
            except KeyboardInterrupt:
                log("Polling stopped by user", tag="INDEXER")
                break
            except Exception as e:
                log(f"Error in polling loop: {e}", tag="INDEXER")
                time.sleep(self.poll_interval)
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection and return cluster info."""
        try:
            if not self.es_client:
                self._connect()
            
            if not self.es_client:
                return {"status": "error", "message": "Failed to connect"}
            
            # Get cluster info
            cluster_info = self.es_client.info()
            
            # Test index access
            indices = self.es_client.indices.resolve_index(name=self.index_pattern)
            
            # Count recent alerts
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=1)
            
            count_query = self._build_query(start_time, end_time)
            count_response = self.es_client.count(
                index=self.index_pattern,
                body={"query": count_query["query"]}
            )
            
            return {
                "status": "success",
                "cluster_name": cluster_info['cluster_name'],
                "version": cluster_info['version']['number'],
                "indices_found": len(indices.get('indices', [])),
                "alerts_last_hour": count_response['count'],
                "index_pattern": self.index_pattern,
                "config": {
                    "url": self.indexer_url,
                    "username": self.username,
                    "verify_certs": self.verify_certs,
                    "poll_interval": self.poll_interval
                }
            }
            
        except Exception as e:
            return {
                "status": "error", 
                "message": str(e)
            }
    
    def get_sample_alert(self) -> Optional[Dict[str, Any]]:
        """Get a sample alert for testing."""
        if not self.es_client:
            return None
            
        try:
            response = self.es_client.search(
                index=self.index_pattern,
                body={
                    "query": {"match_all": {}},
                    "size": 1,
                    "sort": [
                        {self.timestamp_field: {"order": "desc"}}
                    ]
                }
            )
            
            hits = response['hits']['hits']
            if hits:
                return hits[0]['_source']
            else:
                return None
                
        except Exception as e:
            log(f"Error getting sample alert: {e}", tag="INDEXER")
            return None
    
    def store_enriched_alert(self, original_alert: Dict[str, Any], enriched_data: Dict[str, Any]) -> bool:
        """Store enriched alert back to Wazuh Indexer."""
        if not self.es_client or not self.store_enriched:
            return False
            
        try:
            # Create enriched document
            enriched_alert = original_alert.copy()
            
            # Add enrichment metadata
            enrichment_timestamp = datetime.now(timezone.utc).isoformat()
            enriched_alert[f'{self.enrichment_prefix}_timestamp'] = enrichment_timestamp
            enriched_alert[f'{self.enrichment_prefix}_version'] = '1.0'
            
            # Add enriched data under a dedicated namespace
            enriched_alert[self.enrichment_prefix] = enriched_data
            
            # Generate document ID (use original alert ID if available, otherwise timestamp-based)
            doc_id = self._generate_enriched_doc_id(original_alert, enrichment_timestamp)
            
            # Index the enriched alert
            response = self.es_client.index(
                index=self.enriched_index,
                id=doc_id,
                body=enriched_alert
            )
            
            log(f"Stored enriched alert: {doc_id} -> {self.enriched_index}", tag="INDEXER")
            return response.get('result') == 'created' or response.get('result') == 'updated'
            
        except Exception as e:
            log(f"Error storing enriched alert: {e}", tag="INDEXER")
            return False
    
    def store_enriched_alerts_batch(self, enriched_alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Store multiple enriched alerts using bulk API for efficiency."""
        if not self.es_client or not self.store_enriched or not enriched_alerts:
            return {"success": 0, "failed": 0}
            
        try:
            from opensearchpy.helpers import bulk
            
            # Prepare bulk operations
            operations = []
            enrichment_timestamp = datetime.now(timezone.utc).isoformat()
            
            for alert_data in enriched_alerts:
                original_alert = alert_data.get('original', {})
                enriched_data = alert_data.get('enriched', {})
                
                # Create enriched document
                enriched_alert = original_alert.copy()
                enriched_alert[f'{self.enrichment_prefix}_timestamp'] = enrichment_timestamp
                enriched_alert[f'{self.enrichment_prefix}_version'] = '1.0'
                enriched_alert[self.enrichment_prefix] = enriched_data
                
                # Add to bulk operations
                doc_id = self._generate_enriched_doc_id(original_alert, enrichment_timestamp)
                operations.append({
                    "_index": self.enriched_index,
                    "_id": doc_id,
                    "_source": enriched_alert
                })
            
            # Execute bulk operation
            success_count, failed_items = bulk(
                self.es_client,
                operations,
                index=self.enriched_index,
                chunk_size=50,
                request_timeout=60
            )
            
            failed_count = len(failed_items)
            log(f"Bulk stored {success_count} enriched alerts, {failed_count} failed", tag="INDEXER")
            
            return {
                "success": success_count,
                "failed": failed_count,
                "failed_items": failed_items
            }
            
        except Exception as e:
            log(f"Error in bulk store operation: {e}", tag="INDEXER")
            return {"success": 0, "failed": len(enriched_alerts)}
    
    def _generate_enriched_doc_id(self, original_alert: Dict[str, Any], timestamp: str) -> str:
        """Generate a unique document ID for enriched alerts."""
        # Try to use original alert ID if available
        original_id = original_alert.get('id') or original_alert.get('_id')
        if original_id:
            return f"enriched_{original_id}_{timestamp.replace(':', '-')}"
        
        # Fallback to timestamp + rule ID + agent
        rule_id = original_alert.get('rule', {}).get('id', 'unknown')
        agent = original_alert.get('agent', {}).get('name', 'unknown')
        timestamp_short = timestamp[:19].replace(':', '-')  # Remove microseconds and colons
        
        return f"enriched_{timestamp_short}_{rule_id}_{agent}"
    
    def create_enriched_index(self) -> bool:
        """Create the enriched alerts index with proper mapping."""
        if not self.es_client:
            return False
            
        try:
            # Check if index already exists
            if self.es_client.indices.exists(index=self.enriched_index):
                log(f"Enriched index {self.enriched_index} already exists", tag="INDEXER")
                return True
            
            # Create index with mapping
            mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        f"{self.enrichment_prefix}_timestamp": {"type": "date"},
                        f"{self.enrichment_prefix}_version": {"type": "keyword"},
                        self.enrichment_prefix: {
                            "type": "object",
                            "properties": {
                                "analysis": {"type": "text"},
                                "risk_assessment": {"type": "text"},
                                "recommendations": {"type": "text"},
                                "severity": {"type": "keyword"},
                                "confidence": {"type": "float"},
                                "tags": {"type": "keyword"},
                                "ioc_extracted": {"type": "keyword"},
                                "threat_intel": {"type": "object"}
                            }
                        },
                        # Standard Wazuh fields
                        "agent": {"type": "object"},
                        "rule": {"type": "object"},
                        "location": {"type": "keyword"},
                        "full_log": {"type": "text"}
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "refresh_interval": "5s"
                }
            }
            
            response = self.es_client.indices.create(
                index=self.enriched_index,
                body=mapping
            )
            
            log(f"Created enriched index: {self.enriched_index}", tag="INDEXER")
            return response.get('acknowledged', False)
            
        except Exception as e:
            log(f"Error creating enriched index: {e}", tag="INDEXER")
            return False
    
    def cleanup(self):
        """Cleanup resources."""
        if self.es_client:
            try:
                self.es_client.close()
            except Exception:
                pass
