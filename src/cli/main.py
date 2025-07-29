"""
CLI entrypoint for LLM Alert Enrichment Service
"""
import argparse
import sys
import logging
from src.core.service import AlertEnrichmentService
from src.cli.setup import run_setup_wizard, run_auto_setup
from src.cli.push_alert import push_alert_to_indexer
from src.cli.install import install_systemd_service

def main():
    parser = argparse.ArgumentParser(description="LLM Alert Enrichment Service")
    parser.add_argument("command", nargs="?", default="start",
                       choices=["start", "test", "status", "install-service", "setup", "auto", "push-alert"],
                       help="Command to run")
    parser.add_argument("--file", type=str, help="Path to alert JSON file for push-alert command")
    args = parser.parse_args()
    if args.command == "setup":
        run_setup_wizard()
        return
    elif args.command == "auto":
        run_auto_setup()
        return
    elif args.command == "install-service":
        install_systemd_service()
        return
    service = AlertEnrichmentService()
    try:
        if args.command == "start":
            service.start()
        elif args.command == "test":
            success = service.test()
            sys.exit(0 if success else 1)
        elif args.command == "status":
            service.status()
        elif args.command == "push-alert":
            if not args.file:
                print("Please provide --file <path_to_alert_json>")
                sys.exit(1)
            push_alert_to_indexer(service, args.file)
    except KeyboardInterrupt:
        print("\nService interrupted")
    except Exception as e:
        import logging
        logging.error(f"Service error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
