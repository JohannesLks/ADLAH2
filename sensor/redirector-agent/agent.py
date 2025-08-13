import os
import redis
import time
import logging
import json
import subprocess
import threading
from typing import Dict

# --- Configuration ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
REDIS_URL = os.environ.get("REDIS_URL", "redis://10.1.0.10:6379/0")
REDIS_COMMAND_CHANNEL = "redirection-commands"
SENSOR_IP = os.environ.get("SENSOR_IP", "10.1.0.5")
MAINTENANCE_INTERVAL_SEC = 10

# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- State ---
# Thread-safe dictionary to store active rules and their expiry times
# Key: attacker_ip, Value: {"pod_address": "ip:port", "expires_at": timestamp}
active_rules: Dict[str, dict] = {}
lock = threading.Lock()

# --- Helper Functions ---
def run_command(command, check=True):
    """Executes a shell command and logs its output."""
    try:
        logger.info(f"Executing: {' '.join(command)}")
        result = subprocess.run(command, check=check, capture_output=True, text=True, timeout=15)
        if result.stdout:
            logger.info(f"STDOUT: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"STDERR: {result.stderr.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {' '.join(command)}")
        logger.error(f"STDOUT: {e.stdout.strip()}")
        logger.error(f"STDERR: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return False


def apply_redirect_rule(attacker_ip: str, honeypod_ip: str, honeypod_port: int, action: str):
    """Adds or removes iptables rules for an attacker."""
    pod_address = f"{honeypod_ip}:{honeypod_port}"
    logger.info(f"{'Adding' if action == 'add' else 'Removing'} redirect for {attacker_ip} -> {pod_address}")
    
    op_flag = "-I" if action == "add" else "-D"
    chain_pos = "1" if action == "add" else "" # Position only needed for insertion

    # DNAT rule: change destination for incoming packets
    dnat_cmd = [
        "iptables", "-t", "nat", op_flag, "PREROUTING",
        *(filter(None, [chain_pos])), # Add position only for -I
        "-s", attacker_ip, "-p", "tcp", "--dport", "22",
        "-j", "DNAT", "--to-destination", pod_address
    ]
    
    # SNAT rule: change source for outgoing packets so replies are routed correctly
    snat_cmd = [
        "iptables", "-t", "nat", op_flag, "POSTROUTING",
        *(filter(None, [chain_pos])),
        "-s", attacker_ip, "-d", honeypod_ip, "-p", "tcp", "--dport", str(honeypod_port),
        "-j", "SNAT", "--to-source", SENSOR_IP
    ]

    # Execute commands; for deletion, we don't 'check' because the rule might already be gone
    run_command(dnat_cmd, check=(action == 'add'))
    run_command(snat_cmd, check=(action == 'add'))


def handle_message(message: dict):
    """Parses and acts on a command from Redis."""
    try:
        data = json.loads(message['data'])
        action = data.get("action")
        attacker_ip = data.get("attacker_ip")
        honeypod_ip = data.get("honeypod_ip")
        honeypod_port = data.get("honeypod_port")
        ttl = data.get("ttl")

        if not all([action, attacker_ip, honeypod_ip, honeypod_port, ttl]):
            logger.warning(f"Invalid message received: {data}")
            return

        with lock:
            if action == "add":
                apply_redirect_rule(attacker_ip, honeypod_ip, honeypod_port, "add")
                expires_at = time.time() + int(ttl)
                active_rules[attacker_ip] = {
                    "honeypod_ip": honeypod_ip,
                    "honeypod_port": honeypod_port,
                    "expires_at": expires_at
                }
                logger.info(f"Rule for {attacker_ip} added. Expires at {time.ctime(expires_at)}")
            elif action == "remove":
                if attacker_ip in active_rules:
                    rule = active_rules.pop(attacker_ip)
                    apply_redirect_rule(attacker_ip, rule["honeypod_ip"], rule["honeypod_port"], "remove")
                    logger.info(f"Rule for {attacker_ip} removed by command.")
                else:
                    logger.info(f"Received remove command for {attacker_ip}, but no active rule found.")
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Could not process message: {message.get('data', '')}, Error: {e}")


def cleanup_expired_rules():
    """Periodically checks for and removes expired iptables rules."""
    while True:
        time.sleep(MAINTENANCE_INTERVAL_SEC)
        now = time.time()
        
        with lock:
            expired_ips = [
                ip for ip, rule in active_rules.items() if now > rule["expires_at"]
            ]
            
            for ip in expired_ips:
                rule = active_rules.pop(ip)
                logger.info(f"Rule for {ip} has expired. Removing...")
                apply_redirect_rule(ip, rule["honeypod_ip"], rule["honeypod_port"], "remove")


def flush_all_rules():
    """Flushes all PREROUTING and POSTROUTING NAT rules on startup for a clean state."""
    logger.info("Flushing all existing NAT rules for a clean start...")
    run_command(["iptables", "-t", "nat", "-F", "PREROUTING"], check=False)
    run_command(["iptables", "-t", "nat", "-F", "POSTROUTING"], check=False)


def main():
    """Main application loop."""
    logger.info("Starting Redirector Agent...")
    
    flush_all_rules()

    # Start the background cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_rules, daemon=True)
    cleanup_thread.start()
    logger.info(f"Started rule cleanup thread with {MAINTENANCE_INTERVAL_SEC}s interval.")

    # Connect to Redis
    while True:
        try:
            redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(REDIS_COMMAND_CHANNEL)
            logger.info(f"Successfully connected to Redis and subscribed to '{REDIS_COMMAND_CHANNEL}'")
            
            for message in pubsub.listen():
                handle_message(message)

        except redis.exceptions.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"An unexpected error occurred in main loop: {e}", exc_info=True)
            time.sleep(5) # Avoid rapid-fire loop on unexpected errors

if __name__ == "__main__":
    main()