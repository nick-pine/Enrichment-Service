"""
Wazuh Alert Schema Validation
"""
from pydantic import BaseModel, ValidationError
from typing import List, Optional, Dict, Any
import logging

class Rule(BaseModel):
    """Schema for Wazuh rule details."""
    level: Optional[int] = None
    description: Optional[str] = None
    id: Optional[str] = None
    firedtimes: Optional[int] = None
    mail: Optional[bool] = None
    groups: Optional[List[str]] = None
    pci_dss: Optional[List[str]] = None
    gpg13: Optional[List[str]] = None
    gdpr: Optional[List[str]] = None
    hipaa: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    tsc: Optional[List[str]] = None
    mitre: Optional[Dict[str, List[str]]] = None

class Agent(BaseModel):
    """Schema for Wazuh agent details."""
    id: Optional[str] = None
    name: Optional[str] = None

class Manager(BaseModel):
    """Schema for Wazuh manager details."""
    name: Optional[str] = None

class Decoder(BaseModel):
    """Schema for Wazuh decoder details."""
    name: Optional[str] = None
    parent: Optional[str] = None
    ftscomment: Optional[str] = None

class Predecoder(BaseModel):
    """Schema for Wazuh predecoder details."""
    program_name: Optional[str] = None
    timestamp: Optional[str] = None
    hostname: Optional[str] = None

class WazuhAlert(BaseModel):
    """Schema for Wazuh alert validation."""
    timestamp: str = None  # Handle both @timestamp and timestamp
    rule: Rule
    agent: Optional[Agent] = None
    manager: Optional[Manager] = None
    id: Optional[str] = None
    full_log: Optional[str] = None
    decoder: Optional[Decoder] = None
    predecoder: Optional[Predecoder] = None
    location: Optional[str] = None

    class Config:
        extra = "allow"  # Allow extra fields for flexibility

def validate_wazuh_alert(alert_data: Dict[str, Any]) -> bool:
    """
    Validate alert data against Wazuh schema.
    Returns True if valid, False otherwise.
    """
    try:
        # Handle both @timestamp and timestamp fields
        if "@timestamp" in alert_data and "timestamp" not in alert_data:
            alert_data = dict(alert_data)  # Make a copy
            alert_data["timestamp"] = alert_data["@timestamp"]
        
        # Validate against schema
        WazuhAlert(**alert_data)
        return True
        
    except ValidationError as e:
        logging.debug(f"Alert validation failed: {e}")
        return False
    except Exception as e:
        logging.debug(f"Alert validation error: {e}")
        return False

def is_valid_wazuh_alert(alert_data: Dict[str, Any]) -> bool:
    """
    Quick validation - just check for essential fields.
    More permissive than full schema validation.
    """
    try:
        # Must be a dictionary
        if not isinstance(alert_data, dict):
            return False
        
        # Must have timestamp
        if not (alert_data.get("@timestamp") or alert_data.get("timestamp")):
            return False
        
        # Must have rule with level or id
        rule = alert_data.get("rule", {})
        if not isinstance(rule, dict):
            return False
        
        if not (rule.get("level") is not None or rule.get("id") is not None):
            return False
        
        return True
        
    except Exception as e:
        logging.debug(f"Basic alert validation error: {e}")
        return False
