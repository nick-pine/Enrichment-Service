import requests
from requests.auth import HTTPBasicAuth

url = "https://172.17.77.206:9200/wazuh-enriched-alerts/_search?size=5"
user = "admin"
password = "ibDMU16S52t4d26LCATJeJ.bdos6zTJX"

response = requests.get(url, auth=HTTPBasicAuth(user, password), verify=False)
if response.status_code == 200:
    data = response.json()
    print("Found documents:")
    for hit in data.get('hits', {}).get('hits', []):
        print(hit['_id'], hit['_source'])
else:
    print(f"Failed to query index: {response.status_code}")
    print(response.text)
