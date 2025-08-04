import requests
from requests.auth import HTTPBasicAuth

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv(".env")


INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
ENRICHED_INDEX = os.getenv("WAZUH_ENRICHED_INDEX", "wazuh-enriched-alerts")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "changeme")
url = f"{INDEXER_URL}/{ENRICHED_INDEX}/_search?size=5"

response = requests.get(url, auth=HTTPBasicAuth(INDEXER_USER, INDEXER_PASS), verify=False)
if response.status_code == 200:
    data = response.json()
    print("Found documents:")
    for hit in data.get('hits', {}).get('hits', []):
        print(hit['_id'], hit['_source'])
else:
    print(f"Failed to query index: {response.status_code}")
    print(response.text)
