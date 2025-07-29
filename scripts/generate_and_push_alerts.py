import os
import requests
import datetime
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv(".env")

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS")
# Use daily index pattern for dashboard visibility
INDEX_NAME = f"wazuh-alerts-4.x-{datetime.datetime.utcnow().strftime('%Y.%m.%d')}"

# Helper to push alert
def push_alert(alert):
    url = f"{INDEXER_URL}/{INDEX_NAME}/_doc"
    response = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        json=alert,
        verify=False,
        timeout=10
    )
    if response.status_code in [200, 201]:
        print(f"Alert pushed: {response.json().get('_id', 'unknown')}")
    else:
        print(f"Failed to push alert: {response.status_code} {response.text}")

# Generate sample alerts
now = datetime.datetime.utcnow().isoformat()

base_alert = {
    "timestamp": now,
    "@timestamp": now,
    "rule": {
        "level": 12,
        "description": "PAM: Login session opened.",
        "id": "5501",
        "firedtimes": 3,
        "mail": False,
        "groups": ["pam", "syslog", "authentication_success"],
        "pci_dss": ["10.2.5"],
        "gpg13": ["7.8", "7.9"],
        "gdpr": ["IV_32.2"],
        "hipaa": ["164.312.b"],
        "nist_800_53": ["AU.14", "AC.7"],
        "tsc": ["CC6.8", "CC7.2", "CC7.3"],
        "mitre": {
            "technique": ["Valid Accounts"],
            "id": ["T1078"],
            "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]
        }
    },
    "agent": {
        "id": "000",
        "name": "space"
    },
    "manager": {
        "name": "space"
    },
    "id": str(uuid.uuid4()),
    "full_log": "Jul 29 20:20:55 space sudo[3742]: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
    "decoder": {
        "name": "pam",
        "parent": "pam",
        "ftscomment": None
    },
    "predecoder": {
        "program_name": "sudo",
        "timestamp": "Jul 29 20:20:55",
        "hostname": "space"
    },
    "location": "journald"
}

alerts = []

# Critical alert
critical_alert = base_alert.copy()
critical_alert["rule"] = dict(base_alert["rule"])
critical_alert["rule"]["level"] = 12
critical_alert["rule"]["description"] = "Critical SSH brute force detected"
critical_alert["rule"]["groups"] = ["authentication", "ssh"]
critical_alert["severity"] = "critical"
critical_alert["id"] = str(uuid.uuid4())
critical_alert["full_log"] = "Multiple failed SSH login attempts detected from 192.168.1.100"
critical_alert["location"] = "192.168.1.100/sshd"
alerts.append(critical_alert)

# High alert
high_alert = base_alert.copy()
high_alert["rule"] = dict(base_alert["rule"])
high_alert["rule"]["level"] = 8
high_alert["rule"]["description"] = "High disk usage warning"
high_alert["rule"]["groups"] = ["system", "disk"]
high_alert["severity"] = "high"
high_alert["id"] = str(uuid.uuid4())
high_alert["full_log"] = "Disk usage exceeded 90% on /dev/sda1"
high_alert["location"] = "192.168.1.101/disk"
alerts.append(high_alert)

for alert in alerts:
    push_alert(alert)
