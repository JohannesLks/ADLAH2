import os
import redis
import time
import logging
import json
import re
from kubernetes import client, config, watch

# --- Configuration ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))
REDIS_DEPLOY_CHANNEL = "deployment-notifications"
REDIS_MAP_UPDATES_CHANNEL = "map-updates"
REDIS_MAP_HASH_NAME = "attacker_map"
K8S_NAMESPACE = "default"
POD_TTL_SECONDS = 7200 # 2 hours

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Helper Functions ---
def sanitize_ip_for_k8s(ip_address):
    """Sanitizes an IP address to be a valid Kubernetes resource name."""
    return f"cowrie-pod-{ip_address.replace('.', '-')}"

def get_pod_template(pod_name, attacker_ip):
    """Returns a Kubernetes Pod manifest dictionary."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "labels": {
                "app": "cowrie-instance",
                "attacker_ip": attacker_ip
            }
        },
        "spec": {
            "containers": [{
                "name": "cowrie",
                "image": "cowrie/cowrie:latest",
                "ports": [{"containerPort": 2222, "protocol": "TCP"}]
            }],
            "restartPolicy": "Never" # Important for cleanup
        }
    }

# --- Main Application ---
def main():
    """Main application loop."""
    logger.info("Starting Honeypot Orchestrator...")

    # Load Kubernetes configuration (in-cluster)
    try:
        config.load_incluster_config()
        k8s_core_v1 = client.CoreV1Api()
        logger.info("Successfully loaded in-cluster Kubernetes config.")
    except config.ConfigException:
        logger.error("Failed to load in-cluster config. Trying kube_config.")
        config.load_kube_config()
        k8s_core_v1 = client.CoreV1Api()
        logger.info("Successfully loaded kube_config.")


    # Connect to Redis with retry logic
    redis_client = None
    while redis_client is None:
        try:
            redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
            redis_client.ping()
            logger.info(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        except redis.exceptions.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)

    pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(REDIS_DEPLOY_CHANNEL)
    logger.info(f"Subscribed to Redis channel: {REDIS_DEPLOY_CHANNEL}")

    for message in pubsub.listen():
        try:
            data = json.loads(message['data'])
            attacker_ip = data.get("attacker_ip")

            if not attacker_ip:
                logger.warning(f"Received message without attacker_ip: {data}")
                continue

            logger.info(f"Received deployment request for attacker: {attacker_ip}")
            pod_name = sanitize_ip_for_k8s(attacker_ip)

            # Check if pod already exists
            try:
                k8s_core_v1.read_namespaced_pod(name=pod_name, namespace=K8S_NAMESPACE)
                logger.info(f"Pod {pod_name} already exists. Skipping creation.")
                continue
            except client.ApiException as e:
                if e.status != 404:
                    logger.error(f"Error checking for pod {pod_name}: {e}")
                    continue
            
            # Create and launch the pod
            pod_manifest = get_pod_template(pod_name, attacker_ip)
            k8s_core_v1.create_namespaced_pod(body=pod_manifest, namespace=K8S_NAMESPACE)
            logger.info(f"Pod {pod_name} created. Waiting for it to be running...")

            # Watch for pod to be running and get its IP
            w = watch.Watch()
            for event in w.stream(k8s_core_v1.list_namespaced_pod,
                                  namespace=K8S_NAMESPACE,
                                  field_selector=f"metadata.name={pod_name}"):
                pod = event['object']
                if pod.status.phase == 'Running' and pod.status.pod_ip:
                    pod_ip = pod.status.pod_ip
                    logger.info(f"Pod {pod_name} is running with IP: {pod_ip}")
                    
                    # Store mapping in Redis
                    pod_address = f"{pod_ip}:2222"
                    redis_client.hset(REDIS_MAP_HASH_NAME, attacker_ip, pod_address)
                    logger.info(f"Stored mapping in Redis: {attacker_ip} -> {pod_address}")

                    # Publish update notification
                    redis_client.publish(REDIS_MAP_UPDATES_CHANNEL, json.dumps({"attacker_ip": attacker_ip}))
                    logger.info(f"Published update to {REDIS_MAP_UPDATES_CHANNEL}")
                    
                    w.stop()
                    break
                elif pod.status.phase in ['Failed', 'Succeeded']:
                    logger.error(f"Pod {pod_name} entered phase {pod.status.phase}. Aborting.")
                    w.stop()
                    break

        except json.JSONDecodeError:
            logger.error(f"Could not decode JSON from message: {message['data']}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}", exc_info=True)


if __name__ == "__main__":
    main()