"""
Push alert logic for LLM Alert Enrichment Service
"""
import json
import logging
from src.providers.ollama import query_ollama
from src.schemas import EnrichedAlertOutput, WazuhAlertInput, Enrichment
import datetime
import requests

def push_alert_to_indexer(service, alert_file_path):
    logging.info(f"Reading alert from {alert_file_path}")
    try:
        with open(alert_file_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read alert file: {e}")
        return
    enrichment_data = {}
    try:
        enrichment = query_ollama(alert, service.settings.llm_model)
        enrichment_data = enrichment.enrichment.dict() if hasattr(enrichment, 'enrichment') and enrichment.enrichment else {}
    except Exception as e:
        logging.error(f"Error enriching alert: {e}")
        print(f"Enrichment failed, alert will NOT be pushed: {e}")
        return
    type_fields = {
        "tags": list,
        "remediation_steps": list,
        "related_cves": list,
        "external_refs": list,
        "risk_score": int,
        "enrichment_duration_ms": int,
        "false_positive_likelihood": float,
        "yara_matches": list
    }
    for key, expected_type in type_fields.items():
        val = enrichment_data.get(key)
        if isinstance(val, str):
            del enrichment_data[key]
    expected_types = type_fields
    normalized_enrichment = {}
    for key, expected_type in expected_types.items():
        val = enrichment_data.get(key)
        if expected_type == list:
            if isinstance(val, list):
                normalized_enrichment[key] = val
            elif isinstance(val, str):
                normalized_enrichment[key] = [val]
        elif expected_type == int:
            if val is not None:
                try:
                    normalized_enrichment[key] = int(val)
                except (ValueError, TypeError):
                    pass
        elif expected_type == float:
            if val is not None:
                try:
                    normalized_enrichment[key] = float(val)
                except (ValueError, TypeError):
                    pass
    for k, v in enrichment_data.items():
        if k not in expected_types:
            normalized_enrichment[k] = v
    enrichment_data = normalized_enrichment
    try:
        validated_doc = EnrichedAlertOutput(
            alert_id=alert.get("id", ""),
            timestamp=datetime.datetime.utcnow(),
            alert=WazuhAlertInput.from_wazuh_alert(alert),
            enrichment=Enrichment(**enrichment_data)
        )
        doc = validated_doc.dict()
        for k, v in doc.items():
            if isinstance(v, datetime.datetime):
                doc[k] = v.isoformat()
    except Exception as e:
        logging.error(f"Schema validation failed: {e}")
        print(f"Schema validation failed: {e}")
        return
    index_url = f"{service.settings.wazuh_indexer_url}/wazuh-enriched-alerts/_doc"
    try:
        response = requests.post(
            index_url,
            auth=(service.settings.wazuh_indexer_user, service.settings.wazuh_indexer_pass),
            json=doc,
            verify=False,
            timeout=10
        )
        if response.status_code in [200, 201]:
            logging.info(f"Alert pushed to Wazuh Indexer: {response.json().get('_id', 'unknown')}")
            print("Alert successfully pushed to Wazuh Indexer!")
        else:
            logging.error(f"Failed to push alert: {response.status_code} {response.text}")
            print(f"Failed to push alert: {response.status_code}")
    except Exception as e:
        logging.error(f"Error pushing alert: {e}")
        print(f"Error pushing alert: {e}")
