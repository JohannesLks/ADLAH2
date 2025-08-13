#!/usr/bin/env python3
"""
Main entry point for the RL Agent system.

This script initializes the necessary components and starts the event loop
based on the configured data source (Redis or Elasticsearch).
"""
import argparse
import logging
import os
import sys
import time

# Kubernetes imports (optional)
try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    print("WARNING: Kubernetes client not available. Honeypod deployment disabled.")

from .config import system_config
from .logging_setup import setup_logging
from .event_loop import EventLoop, ElasticsearchEventSource
from .es import create_es_client
from .k8s import HoneypodManager


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="RL Agent for adaptive honeypod deployment")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without actually deploying honeypods"
    )
    return parser.parse_args()


def setup_kubernetes():
    """Initialize Kubernetes clients."""
    log = logging.getLogger(__name__)
    log.info("K8S_SETUP: Attempting to set up Kubernetes...")

    if not K8S_AVAILABLE:
        log.warning("K8S_SETUP: Kubernetes client library not installed.")
        return None, None

    try:
        kubeconfig_path = os.getenv("KUBECONFIG")
        if kubeconfig_path and os.path.exists(kubeconfig_path):
            log.info(f"K8S_SETUP: Loading kubeconfig from {kubeconfig_path}...")
            config.load_kube_config(config_file=kubeconfig_path)
            log.info("K8S_SETUP: Successfully loaded kubeconfig.")
        else:
            # Try in-cluster only if the env indicates we're in Kubernetes
            if os.getenv("KUBERNETES_SERVICE_HOST"):
                log.info("K8S_SETUP: Loading in-cluster config...")
                config.load_incluster_config()
                log.info("K8S_SETUP: Successfully loaded in-cluster config.")
            else:
                log.info("K8S_SETUP: No kubeconfig and not in cluster; skipping K8s setup.")
                return None, None
        
        # Create and return API clients
        apps_v1 = client.AppsV1Api()
        core_v1 = client.CoreV1Api()
        log.info("K8S_SETUP: API clients created successfully.")
        return apps_v1, core_v1

    except config.ConfigException as e:
        log.error(f"K8S_SETUP: Failed to load in-cluster config: {e}", exc_info=True)
        return None, None
    except Exception as e:
        log.error(f"K8S_SETUP: A fatal error occurred during Kubernetes setup: {e}", exc_info=True)
        return None, None


def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    log = logging.getLogger(__name__)
    
    log.info("Starting RL Agent")
    log.info(f"Configuration: source=elasticsearch, dry_run={args.dry_run}")
    
    # Initialize event source
    log.info("Using Elasticsearch as event source")
    es_client = None
    for i in range(10):
        try:
            es_client = create_es_client()
            log.info("Successfully connected to Elasticsearch")
            break
        except Exception as e:
            log.warning(f"Failed to connect to Elasticsearch (attempt {i+1}/10), retrying in 10s: {e}")
            time.sleep(10)
    
    if not es_client:
        log.error("Could not connect to Elasticsearch after multiple retries, exiting.")
        sys.exit(1)

    event_source = ElasticsearchEventSource(es_client)
    
    # Initialize Kubernetes if not in dry-run mode (allow kubeconfig outside cluster)
    apps_api = None
    core_api = None
    if not args.dry_run:
        apps_api, core_api = setup_kubernetes()
        if apps_api and core_api:
            log.info("K8S_MAIN: Kubernetes integration enabled.")
        else:
            log.warning("K8S_MAIN: Kubernetes not configured; running in observation mode only.")
    else:
        log.info("Dry-run mode - no honeypods will be deployed")
    
    # Create and run event loop
    try:
        event_loop = EventLoop(es_client, apps_api, core_api)
        event_loop.run()
    except KeyboardInterrupt:
        log.info("Received interrupt signal, shutting down...")
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()