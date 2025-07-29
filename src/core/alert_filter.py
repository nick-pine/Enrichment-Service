"""
Alert filtering module for the LLM enrichment engine.
Filters alerts based on severity, type, and other criteria before enrichment.
"""

import re
from typing import Dict, List, Any, Optional
from src.core.logger import log

class AlertFilter:
    """Filters alerts based on configurable criteria."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the alert filter with configuration."""
        self.config = config or {}
        
        # Default severity levels (from lowest to highest priority)
        self.severity_levels = {
            'low': 1,
            'medium': 2, 
            'high': 3,
            'critical': 4,
            'info': 1,  # alias for low
            'warning': 2,  # alias for medium
            'error': 3,  # alias for high
            'alert': 4  # alias for critical
        }
        
        # Load configuration
        self.min_severity = self.config.get('min_severity', 'medium')
        self.max_severity = self.config.get('max_severity', 'critical')
        self.allowed_severities = self.config.get('allowed_severities', [])
        self.blocked_severities = self.config.get('blocked_severities', [])
        
        # Rule-based filtering
        self.allowed_rules = self.config.get('allowed_rules', [])
        self.blocked_rules = self.config.get('blocked_rules', [])
        self.rule_patterns = self.config.get('rule_patterns', [])
        
        # Source filtering
        self.allowed_sources = self.config.get('allowed_sources', [])
        self.blocked_sources = self.config.get('blocked_sources', [])
        
        # Custom field filtering
        self.custom_filters = self.config.get('custom_filters', {})
        
        # Risk score filtering
        self.min_risk_score = self.config.get('min_risk_score', 0)
        self.max_risk_score = self.config.get('max_risk_score', 100)
        
        log(f"Alert filter initialized with min_severity: {self.min_severity}", tag="FILTER")
    
    def should_enrich_alert(self, alert: Dict[str, Any]) -> tuple[bool, str]:
        """
        Determine if an alert should be enriched based on filtering criteria.
        
        Returns:
            tuple: (should_enrich: bool, reason: str)
        """
        try:
            # Check severity filtering
            if not self._check_severity(alert):
                severity = self._get_alert_severity(alert)
                return False, f"Severity '{severity}' below threshold '{self.min_severity}'"
            
            # Check allowed/blocked severities
            if not self._check_severity_lists(alert):
                severity = self._get_alert_severity(alert)
                return False, f"Severity '{severity}' not in allowed list or is blocked"
            
            # Check rule filtering
            if not self._check_rules(alert):
                rule_id = self._get_rule_id(alert)
                return False, f"Rule '{rule_id}' is blocked or not in allowed list"
            
            # Check source filtering
            if not self._check_sources(alert):
                source = self._get_alert_source(alert)
                return False, f"Source '{source}' is blocked or not in allowed list"
            
            # Check risk score filtering
            if not self._check_risk_score(alert):
                risk_score = self._get_risk_score(alert)
                return False, f"Risk score {risk_score} outside allowed range"
            
            # Check custom filters
            custom_result, custom_reason = self._check_custom_filters(alert)
            if not custom_result:
                return False, f"Custom filter: {custom_reason}"
            
            return True, "Alert passed all filters"
            
        except Exception as e:
            log(f"Error in alert filtering: {e}", tag="FILTER")
            # Default to allowing enrichment if filtering fails
            return True, f"Filter error (allowing): {e}"
    
    def _get_alert_severity(self, alert: Dict[str, Any]) -> str:
        """Extract severity from alert in various formats."""
        
        # First, check for Wazuh rule level and map to severity
        if 'rule' in alert and isinstance(alert['rule'], dict):
            rule = alert['rule']
            if 'level' in rule:
                level = rule['level']
                if isinstance(level, (int, str)):
                    try:
                        level_num = int(level)
                        # Map Wazuh rule levels to severity strings
                        # Critical = rule level 15 or higher
                        # High = 12 - 14
                        # Medium = 7 - 11
                        # Low = 0 - 6
                        if level_num >= 15:
                            return 'critical'
                        elif level_num >= 12:
                            return 'high'
                        elif level_num >= 7:
                            return 'medium'
                        else:  # level 0-6
                            return 'low'
                    except (ValueError, TypeError):
                        pass
        
        # Try common severity field names if rule level mapping didn't work
        severity_fields = [
            'severity',
            'level', 
            'priority',
            'classification',
            'alert_severity',
            'rule_level'
        ]
        
        for field in severity_fields:
            if field in alert:
                severity = str(alert[field]).lower().strip()
                if severity in ['info', 'low', 'medium', 'high', 'critical', 'warning', 'error', 'alert']:
                    return severity
        
        # Check nested fields
        if 'rule' in alert and isinstance(alert['rule'], dict):
            rule = alert['rule']
            for field in severity_fields:
                if field in rule:
                    severity = str(rule[field]).lower().strip()
                    if severity in ['info', 'low', 'medium', 'high', 'critical', 'warning', 'error', 'alert']:
                        return severity
        
        # Check Wazuh-specific fields
        if 'decoder' in alert and isinstance(alert['decoder'], dict):
            decoder = alert['decoder']
            if 'name' in decoder and 'syslog' in decoder['name'].lower():
                # Extract from syslog priority if available
                if 'priority' in alert:
                    priority = alert['priority']
                    if isinstance(priority, int):
                        if priority <= 3:
                            return 'critical'
                        elif priority <= 6:
                            return 'high'
                        else:
                            return 'medium'
        
        # Default to medium if no severity found
        return 'medium'
    
    def _check_severity(self, alert: Dict[str, Any]) -> bool:
        """Check if alert severity meets minimum threshold."""
        if not self.min_severity:
            return True
        
        alert_severity = self._get_alert_severity(alert)
        
        # Get numeric values for comparison
        alert_level = self.severity_levels.get(alert_severity, 2)  # Default to medium
        min_level = self.severity_levels.get(self.min_severity.lower(), 2)
        max_level = self.severity_levels.get(self.max_severity.lower(), 4) if self.max_severity else 4
        
        return min_level <= alert_level <= max_level
    
    def _check_severity_lists(self, alert: Dict[str, Any]) -> bool:
        """Check allowed/blocked severity lists."""
        alert_severity = self._get_alert_severity(alert)
        
        # Check blocked severities first
        if self.blocked_severities and alert_severity in [s.lower() for s in self.blocked_severities]:
            return False
        
        # Check allowed severities
        if self.allowed_severities and alert_severity not in [s.lower() for s in self.allowed_severities]:
            return False
        
        return True
    
    def _get_rule_id(self, alert: Dict[str, Any]) -> str:
        """Extract rule ID from alert."""
        if 'rule' in alert and isinstance(alert['rule'], dict):
            rule = alert['rule']
            return str(rule.get('id', rule.get('name', rule.get('description', 'unknown'))))
        
        return str(alert.get('rule_id', alert.get('signature_id', 'unknown')))
    
    def _check_rules(self, alert: Dict[str, Any]) -> bool:
        """Check rule-based filtering."""
        rule_id = self._get_rule_id(alert)
        
        # Check blocked rules
        if self.blocked_rules and rule_id in self.blocked_rules:
            return False
        
        # Check allowed rules
        if self.allowed_rules and rule_id not in self.allowed_rules:
            return False
        
        # Check rule patterns
        if self.rule_patterns:
            rule_text = f"{rule_id} {alert.get('rule', {}).get('description', '')}"
            for pattern in self.rule_patterns:
                try:
                    if re.search(pattern, rule_text, re.IGNORECASE):
                        return True
                except re.error:
                    log(f"Invalid regex pattern: {pattern}", tag="FILTER")
            # If patterns are defined but none match, block
            return False
        
        return True
    
    def _get_alert_source(self, alert: Dict[str, Any]) -> str:
        """Extract source from alert."""
        source_fields = ['agent', 'host', 'source', 'src_ip', 'hostname']
        
        for field in source_fields:
            if field in alert:
                if isinstance(alert[field], dict):
                    return str(alert[field].get('name', alert[field].get('ip', str(alert[field]))))
                else:
                    return str(alert[field])
        
        return 'unknown'
    
    def _check_sources(self, alert: Dict[str, Any]) -> bool:
        """Check source-based filtering."""
        source = self._get_alert_source(alert)
        
        # Check blocked sources
        if self.blocked_sources and source in self.blocked_sources:
            return False
        
        # Check allowed sources
        if self.allowed_sources and source not in self.allowed_sources:
            return False
        
        return True
    
    def _get_risk_score(self, alert: Dict[str, Any]) -> float:
        """Extract risk score from alert."""
        risk_fields = ['risk_score', 'score', 'confidence', 'threat_score']
        
        for field in risk_fields:
            if field in alert:
                try:
                    return float(alert[field])
                except (ValueError, TypeError):
                    continue
        
        # Calculate based on severity if no explicit score
        severity = self._get_alert_severity(alert)
        severity_scores = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        return severity_scores.get(severity, 50)
    
    def _check_risk_score(self, alert: Dict[str, Any]) -> bool:
        """Check risk score filtering."""
        if self.min_risk_score == 0 and self.max_risk_score == 100:
            return True
        
        risk_score = self._get_risk_score(alert)
        return self.min_risk_score <= risk_score <= self.max_risk_score
    
    def _check_custom_filters(self, alert: Dict[str, Any]) -> tuple[bool, str]:
        """Check custom field-based filters."""
        if not self.custom_filters:
            return True, ""
        
        for field_path, criteria in self.custom_filters.items():
            try:
                # Get field value using dot notation (e.g., "rule.level")
                value = self._get_nested_field(alert, field_path)
                
                # Check criteria
                if isinstance(criteria, dict):
                    if 'equals' in criteria and value != criteria['equals']:
                        return False, f"{field_path} != {criteria['equals']}"
                    if 'contains' in criteria and criteria['contains'] not in str(value):
                        return False, f"{field_path} does not contain {criteria['contains']}"
                    if 'regex' in criteria:
                        try:
                            if not re.search(criteria['regex'], str(value), re.IGNORECASE):
                                return False, f"{field_path} does not match pattern {criteria['regex']}"
                        except re.error:
                            log(f"Invalid regex in custom filter: {criteria['regex']}", tag="FILTER")
                elif isinstance(criteria, list):
                    if value not in criteria:
                        return False, f"{field_path} not in allowed values"
                else:
                    if value != criteria:
                        return False, f"{field_path} != {criteria}"
                        
            except Exception as e:
                log(f"Error checking custom filter {field_path}: {e}", tag="FILTER")
                continue
        
        return True, ""
    
    def _get_nested_field(self, data: Dict[str, Any], field_path: str) -> Any:
        """Get nested field value using dot notation."""
        fields = field_path.split('.')
        current = data
        
        for field in fields:
            if isinstance(current, dict) and field in current:
                current = current[field]
            else:
                return None
        
        return current
    
    def get_filter_stats(self) -> Dict[str, Any]:
        """Get filter configuration for debugging."""
        return {
            'min_severity': self.min_severity,
            'max_severity': self.max_severity,
            'allowed_severities': self.allowed_severities,
            'blocked_severities': self.blocked_severities,
            'allowed_rules': len(self.allowed_rules) if self.allowed_rules else 0,
            'blocked_rules': len(self.blocked_rules) if self.blocked_rules else 0,
            'rule_patterns': len(self.rule_patterns) if self.rule_patterns else 0,
            'custom_filters': len(self.custom_filters) if self.custom_filters else 0,
            'risk_score_range': f"{self.min_risk_score}-{self.max_risk_score}"
        }
