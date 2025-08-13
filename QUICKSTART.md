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
  sudo ./start_enrichment.sh
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

## 6b. Add YARA Rules
YARA rules are used for threat detection and enrichment. Add your custom rules to the `yara_rules/` directory:
```
cp yara_rules/example_rule.yar yara_rules/my_custom_rule.yar
# Edit `my_custom_rule.yar` to define your own rules
```
You can add as many `.yar` files as needed. The service will automatically load all rules in this directory.


## 6a. Fix Permissions (if needed)
If you see permission errors in the logs, run:
```
sudo chown -R wazuh:wazuh /home/user/Enrichment-Service
sudo chmod o+x /home/user
sudo chown -R wazuh:wazuh /home/user/Enrichment-Service/logs
sudo chown wazuh:wazuh /home/user/Enrichment-Service/.env
sudo chown -R wazuh:wazuh /home/user/Enrichment-Service/templates
sudo systemctl restart llm-enrichment.service
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

# 9. Wazuh Dashboard View
- A pattern-index and custom dashboard were created to accompany the enrichment service
- In the Wazuh Dashboard, under Saved Objects, click import and select `alert-enrichment-saved-objects.ndjson`

## 10. Few-Shot Model (if needed)
- Embeds examples of sucessful output in the model, improving performance
- Place examples in JSON format in `format_data.py` (50-100 recommended), then run the script. By default uses synthesized examples
- Run `few_shot.py.` Use the generated modelfile to create a new model with Ollama. Parameters can be edited for further customization
```
ollama create <custom-model-name> -f Modelfile.<custom-model-name>
```
- Edit `.env` to use the custom model 
- PLEASE NOTE - Using output from a Llama 3 model to train/improve a non-Llama 3 model is a violation of the Meta Llama 3 License
---
For advanced configuration, see the README or docs folder.
