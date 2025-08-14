import json
import jsonlines # type: ignore
from typing import Dict, List, Any
from datetime import datetime
import os

class FormatTrainingData:
    def __init__(self):
        self.prompt = """You are a security enrichment assistant.
ALWAYS respond with ONLY a single valid JSON object. NO markdown, NO newlines, NO extra text. Output should be raw JSON. Example:
{"summary_text": "Example summary.", "tags": ["pam", "authentication_success"], "risk_score": 0.2, "false_positive_likelihood": 0.05, "alert_category": "Authentication", "remediation_steps": ["Review sudoers configuration."], "related_cves": [], "external_refs": []}
INSTRUCTIONS:
- All property names and string values MUST use double quotes.
- For unknown fields, use "", 0, 0.0, or [].
- Output only these fields, in this order.
- DO NOT add any extra fields, explanation, markdown, or whitespace.
- Do NOT wrap the JSON in single or double quotes.
- Do NOT output the JSON as a string. Output only the raw JSON object.
- If you cannot comply, output: {"summary_text": "ERROR", ...}
Alert JSON:
{alert_json}
YARA Matches:
{yara_results}"""

    def create_training_data(self, alert_data: Dict, yara_results: List, expected_response: Dict) -> Dict:       
        alert_json_str = json.dumps(alert_data, indent=2)
        yara_results_str = json.dumps(yara_results, indent=2) if yara_results else "[]"
        formatted_prompt = self.prompt.replace("{alert_json}", alert_json_str).replace("{yara_results}", yara_results_str)
        response_json = json.dumps(expected_response, separators=(',', ':'))
        
        # Return in Llama 3 chat format
        return {
            "messages": [
                {
                    "role": "user",
                    "content": formatted_prompt
                },
                {
                    "role": "assistant", 
                    "content": response_json
                }
            ]
        }
    
    def synthesized_data(self) -> List[Dict]:
        """Data synthesized by AI, USED FOR DEMONSTRATION. Add real enriched alerts for better quality training data"""
        
        training_examples = []
        
        alert1 = {
            "id": "1736946738.492.critical.001",
            "timestamp": "2025-01-15T14:32:18.000Z",
            "rule": {
                "id": "31001",
                "level": 12,
                "description": "Multiple authentication failures followed by successful login",
                "groups": ["authentication_failed", "authentication_success", "attack"]
            },
            "full_log": "Jan 15 14:32:18 web-server-prod-01 sshd[24589]: Accepted password for admin from 185.220.101.182 port 52847 ssh2",
            "data": {
                "srcip": "185.220.101.182",
                "srcport": "52847", 
                "srcuser": "admin",
                "protocol": "ssh"
            },
            "agent": {"name": "web-server-prod-01"}
        }
        
        response1 = {
            "summary_text": "SSH brute force attack successfully compromised admin account from suspicious IP",
            "tags": ["ssh", "brute_force", "authentication_success", "compromise"],
            "risk_score": 0.95,
            "false_positive_likelihood": 0.05,
            "alert_category": "Authentication Attack",
            "remediation_steps": [
                "Immediately block source IP 185.220.101.182",
                "Reset admin account password", 
                "Review SSH logs for lateral movement",
                "Implement SSH key-based authentication"
            ],
            "related_cves": ["CVE-2023-38408"],
            "external_refs": ["https://attack.mitre.org/techniques/T1110/"]
        }
        
        training_examples.append(
            self.create_training_data(alert1, [], response1)
        )
        
        alert2 = {
            "id": "1736946800.123.high.002", 
            "timestamp": "2025-01-15T15:45:22.000Z",
            "rule": {
                "id": "554",
                "level": 7,
                "description": "File added to the system",
                "groups": ["ossec", "syscheck", "syscheck_file"]
            },
            "full_log": "ossec: File '/tmp/malicious_script.sh' added",
            "data": {
                "filename": "/tmp/malicious_script.sh",
                "md5_after": "d41d8cd98f00b204e9800998ecf8427e"
            },
            "agent": {"name": "workstation-01"}
        }
        
        yara2 = [
            {
                "rule": "Suspicious_Shell_Script",
                "tags": ["malware", "shell"],
                "meta": {"description": "Detects suspicious shell script patterns"}
            }
        ]
        
        response2 = {
            "summary_text": "Suspicious shell script detected in temporary directory with YARA malware signatures",
            "tags": ["malware", "file_creation", "shell_script", "yara_detection"],
            "risk_score": 0.85,
            "false_positive_likelihood": 0.1,
            "alert_category": "Malware",
            "remediation_steps": [
                "Quarantine file /tmp/malicious_script.sh",
                "Run full system antivirus scan",
                "Check process history for script execution",
                "Review file download sources"
            ],
            "related_cves": [],
            "external_refs": ["https://attack.mitre.org/techniques/T1059/004/"]
        }
        
        training_examples.append(
            self.create_training_data(alert2, yara2, response2)
        )
        
        alert3 = {
            "id": "1736946850.456.low.003",
            "timestamp": "2025-01-15T16:20:10.000Z", 
            "rule": {
                "id": "2503",
                "level": 3,
                "description": "Service started",
                "groups": ["service", "systemd"]
            },
            "full_log": "systemd[1]: Started Apache HTTP Server",
            "data": {
                "service": "apache2",
                "action": "started"
            },
            "agent": {"name": "web-server-02"}
        }
        
        response3 = {
            "summary_text": "Normal Apache service restart detected on web server",
            "tags": ["service_management", "apache", "systemd", "normal_operation"],
            "risk_score": 0.1,
            "false_positive_likelihood": 0.9,
            "alert_category": "System Management", 
            "remediation_steps": [
                "Verify service restart was planned",
                "Check service logs for errors"
            ],
            "related_cves": [],
            "external_refs": []
        }
        
        training_examples.append(
            self.create_training_data(alert3, [], response3)
        )
        
        alert4 = {
            "id": "1736946900.789.critical.004",
            "timestamp": "2025-01-15T17:10:30.000Z",
            "rule": {
                "id": "5402", 
                "level": 10,
                "description": "Successful sudo to root executed",
                "groups": ["sudo", "pam", "privilege_escalation"]
            },
            "full_log": "sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash",
            "data": {
                "srcuser": "user1",
                "dstuser": "root",
                "command": "/bin/bash"
            },
            "agent": {"name": "critical-server-01"}
        }
        
        response4 = {
            "summary_text": "User escalated privileges to root shell access on critical server",
            "tags": ["privilege_escalation", "sudo", "root_access", "shell"],
            "risk_score": 0.7,
            "false_positive_likelihood": 0.2,
            "alert_category": "Privilege Escalation",
            "remediation_steps": [
                "Verify user1 authorization for root access",
                "Review sudo configuration and policies", 
                "Monitor subsequent root activities",
                "Check if escalation was part of approved maintenance"
            ],
            "related_cves": [],
            "external_refs": ["https://attack.mitre.org/techniques/T1548/003/"]
        }
        
        training_examples.append(
            self.create_training_data(alert4, [], response4)
        )
        
        return training_examples

    def save_training_data(self, examples: List[Dict], filename: str = "training_data.jsonl"):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        modelfile_path = os.path.join(script_dir, filename)

        with jsonlines.open(modelfile_path, mode='w') as writer:
            for example in examples:
                writer.write(example)

    def validate_json_response(self, response: str) -> bool:
        required_fields = [
            "summary_text", "tags", "risk_score", "false_positive_likelihood",
            "alert_category", "remediation_steps", "related_cves", "external_refs"
        ]
        
        try:
            parsed = json.loads(response)
            return all(field in parsed for field in required_fields)
        except json.JSONDecodeError:
            return False

def main():
    generator = FormatTrainingData()
    training_examples = generator.synthesized_data()    
    generator.save_training_data(training_examples)
    
if __name__ == "__main__":
    main()

