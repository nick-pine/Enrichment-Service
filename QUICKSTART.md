# LLM Alert Enrichment Service - Quickstart Guide

## Prerequisites
- Ubuntu/Debian VM with Python 3, Wazuh, and Ollama installed
- Git installed

## 1. Clone the Repository
```
git clone <your-repo-url>
cd Enrichment-Service
```


## 2. Configure and Test Environment
- Run the quick deploy script:
  ```
  chmod +x start_enrichment.sh
  ./start_enrichment.sh
  ```
  - This will copy `.env.example` to `.env` if needed.
- Edit `.env` with your Wazuh and Ollama settings if you need to change defaults.

## 4. Install and Start the Systemd Service
```
chmod +x install_service.sh
./install_service.sh
```
- This script will:
  - Create the `wazuh` user/group if missing
  - Install Python dependencies system-wide
  - Set directory and log file permissions
  - Copy and enable the systemd unit file
  - Start the enrichment service

## 5. Check Service Status
```
sudo systemctl status llm-enrichment.service
```
- Should show `active (running)`

## 6. View Logs
```
sudo tail -f /var/log/llm-enrichment.log
sudo tail -f /var/log/llm-enrichment-error.log
```

## 7. Troubleshooting
- If the service fails, check the error log above
- Ensure all environment variables in `.env` are correct
- Make sure Wazuh and Ollama are running and accessible

## 8. Updating the Service
- Pull new changes:
```
git pull
```
- Re-run the install script:
```
./install_service.sh
```

---
For advanced configuration, see the README or docs folder.
