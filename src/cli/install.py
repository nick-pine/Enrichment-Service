"""
Install systemd service logic for LLM Alert Enrichment Service
"""
import os
import subprocess

def install_systemd_service():
    if os.name != 'posix':
        print("This command is only available on Linux systems")
        return
    service_file = "/etc/systemd/system/llm-enrichment.service"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    service_content = f"""[Unit]
Description=LLM Alert Enrichment Service
After=network.target wazuh-indexer.service

[Service]
Type=simple
User=wazuh
Group=wazuh
WorkingDirectory={current_dir}
Environment=PATH={current_dir}/venv/bin
ExecStart={current_dir}/venv/bin/python {current_dir}/enrichment_service.py start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    try:
        with open("/tmp/llm-enrichment.service", "w") as f:
            f.write(service_content)
        subprocess.run(["sudo", "mv", "/tmp/llm-enrichment.service", service_file], check=True)
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "llm-enrichment"], check=True)
        print("Service installed successfully!")
        print("Commands:")
        print("  sudo systemctl start llm-enrichment     # Start service")
        print("  sudo systemctl stop llm-enrichment      # Stop service")
        print("  sudo systemctl status llm-enrichment    # Check status")
        print("  sudo journalctl -u llm-enrichment -f    # View logs")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install service: {e}")
        print("Make sure you have sudo privileges")
    except PermissionError:
        print("Permission denied. Run with sudo or as root.")
    except Exception as e:
        print(f"Error installing service: {e}")
