
import sys
import os
import requests
import datetime
import uuid
from dotenv import load_dotenv

def check_env(var, name):
    if not var:
        print(f"Error: Missing environment variable {name} in .env file.")
        sys.exit(1)

def main():
    # Load environment variables
    load_dotenv(".env")

    INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
    INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
    INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS")
    check_env(INDEXER_URL, "WAZUH_INDEXER_URL")
    check_env(INDEXER_USER, "WAZUH_INDEXER_USER")
    check_env(INDEXER_PASS, "WAZUH_INDEXER_PASS")

    INDEX_NAME = f"wazuh-alerts-4.x-{datetime.datetime.utcnow().strftime('%Y.%m.%d')}"

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
            return True
        else:
            print(f"Failed to push alert: {response.status_code} {response.text}")
            return False

    # Number of alerts to generate (default 2)
    alert_count = 2
    if len(sys.argv) > 1:
        try:
            alert_count = int(sys.argv[1])
        except ValueError:
            print("Usage: python generate_and_push_alerts.py [alert_count]")
            sys.exit(1)

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
    # Generate alerts
    for i in range(alert_count):
        alert = base_alert.copy()
        alert["id"] = str(uuid.uuid4())
        if i % 2 == 0:
            alert["rule"] = dict(base_alert["rule"])
            alert["rule"]["level"] = 12
            alert["rule"]["description"] = f"Critical SSH brute force detected {i+1}"
            alert["rule"]["groups"] = ["authentication", "ssh"]
            alert["severity"] = "critical"
            alert["full_log"] = f"Multiple failed SSH login attempts detected from 192.168.1.{100+i}"
            alert["location"] = f"192.168.1.{100+i}/sshd"
        else:
            alert["rule"] = dict(base_alert["rule"])
            alert["rule"]["level"] = 8
            alert["rule"]["description"] = f"High disk usage warning {i+1}"
            alert["rule"]["groups"] = ["system", "disk"]
            alert["severity"] = "high"
            alert["full_log"] = f"Disk usage exceeded 90% on /dev/sda{i+1}"
            alert["location"] = f"192.168.1.{101+i}/disk"
        alerts.append(alert)

    success_count = 0
    for alert in alerts:
        if push_alert(alert):
            success_count += 1

    print(f"\nSummary: {success_count}/{alert_count} alerts pushed successfully.")

if __name__ == "__main__":
    main()
