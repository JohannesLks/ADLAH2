"""
Unified event loop for processing log events and managing RL agent decisions.
"""
import atexit
import logging
import time
import threading
import json
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, Deque, Optional, Tuple
import subprocess
import asyncio
import concurrent.futures
import logging
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone
from memory_profiler import profile

# Required imports for type annotations
from elasticsearch import Elasticsearch
from kubernetes import client

import numpy as np

from .config import agent_config, system_config, feature_config
from .features import extract_features, save_feature_stats, FeatureExtractor
from .agent import ACTIONS, DQNAgent
from .inference import create_inference_service
from .k8s import HoneypodManager
from .es import ElasticsearchClient, RedisPublisher
from .connection_tracker import ConnectionTracker

log = logging.getLogger(__name__)


class EventSource(ABC):
    """Abstract base class for event sources."""
    
    @abstractmethod
    def get_events(self):
        """Yield log events from the source."""
        pass


class ElasticsearchEventSource(EventSource):
    """Elasticsearch polling event source."""
    
    def __init__(self, es_client: ElasticsearchClient):
        self.es_client = es_client
        # Start slightly in the past to avoid missing recent events on startup
        try:
            lookback_sec = max(60, int(system_config.window_sec))
        except Exception:
            lookback_sec = 300
        self.last_timestamp = datetime.now(timezone.utc) - timedelta(seconds=lookback_sec)
        log.info(f"Polling Elasticsearch index: {system_config.es_index_pattern}")
    
    def get_events(self):
        """Yield events from Elasticsearch."""
        no_docs_counter = 0
        while True:
            try:
                docs = self.es_client.get_recent_logs(
                    since=self.last_timestamp,
                    limit=system_config.es_batch_size
                )
                
                if not docs:
                    no_docs_counter += 1
                    if no_docs_counter % 30 == 0:  # log roughly every ~30 fetch cycles
                        log.info(
                            f"ES_SOURCE: No new documents found since {self.last_timestamp.isoformat()} "
                            f"in index pattern '{system_config.es_index_pattern}'."
                        )
                else:
                    no_docs_counter = 0

                for doc in docs:
                    yield doc
                    # Update timestamp
                    if '@timestamp' in doc:
                        doc_time = datetime.fromisoformat(doc['@timestamp'].replace('Z', '+00:00'))
                        if doc_time > self.last_timestamp:
                            self.last_timestamp = doc_time
                
                time.sleep(system_config.es_poll_interval)
                
            except Exception as e:
                log.error(f"Error polling Elasticsearch: {e}")
                time.sleep(5)


class EventLoop:
    """Main event loop for processing logs and making deployment decisions."""
    
    @profile(precision=4, stream=open('/tmp/memory_profiler.log', 'w+'))
    def __init__(self, es_client: Elasticsearch, k8s_apps_api: Optional[client.AppsV1Api] = None,
                 k8s_core_api: Optional[client.CoreV1Api] = None):
        self.es_client = es_client
        self.k8s_apps_api = k8s_apps_api
        self.k8s_core_api = k8s_core_api
        self.agent = DQNAgent()
        self.feature_extractor = FeatureExtractor()
        # Only enable Kubernetes integration when both APIs are provided
        self.honeypod_manager = (
            HoneypodManager(k8s_apps_api, k8s_core_api)
            if (k8s_apps_api is not None and k8s_core_api is not None)
            else None
        )
        self.connection_tracker = ConnectionTracker()
        self.config = system_config
        try:
            self.redis_publisher = RedisPublisher()
        except ConnectionError:
            self.redis_publisher = None
            log.error("Failed to create Redis publisher. Redirection commands will be disabled.")

        # Create event source for Elasticsearch
        self.event_source = ElasticsearchEventSource(es_client)

        # Threading and synchronization
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # State tracking for processing
        self.last_timestamp = defaultdict(float)  # Per-IP last seen timestamp
        self.ip_buffers = defaultdict(lambda: deque(maxlen=agent_config.sequence_length))
        self.last_deploy_time: Dict[str, float] = {}
        self.pending_deploys: Dict[str, tuple[np.ndarray, float]] = {}
        # Pending transitions awaiting next_state (per IP)
        self.pending_transitions: Dict[str, tuple[np.ndarray, str, float, float]] = {}
        
        # Create inference service
        self.inference_service = create_inference_service(self.agent)
        
        # Statistics tracking
        self.stats = defaultdict(int)
        
        # High-scale processing
        self.deployment_semaphore = asyncio.Semaphore(self.config.max_concurrent_deployments)
        self.ssh_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.ssh_connection_pool_size,
            thread_name_prefix="ssh-worker"
        )
        
        # State tracking for high-scale operation
        self.ip_last_seen: Dict[str, datetime] = {}
        self.ip_last_decision: Dict[str, datetime] = {}
        self.active_deployments: Set[str] = set()
        self.deployment_queue: asyncio.Queue = asyncio.Queue()
        
        # Batch processing
        self.pending_decisions: Dict[str, dict] = {}
        self.batch_timer: Optional[asyncio.Task] = None
    
    def _maintenance_loop(self):
        """Periodically run maintenance tasks in a separate thread."""
        interval = system_config.maintenance_interval_sec
        log.info(f"Starting maintenance loop with {interval}s interval.")
        
        while not self._stop_event.wait(interval):
            try:
                log.info("Running periodic maintenance...")
                with self.lock:
                    self._periodic_maintenance()
            except Exception as e:
                log.error(f"Error in maintenance loop: {e}", exc_info=True)

    @profile(precision=4, stream=open('/tmp/memory_profiler.log', 'w+'))
    def run(self) -> None:
        """Run the main event processing loop."""
        log.info("EVENT_LOOP: Starting event loop RUN")
        
        for doc in self.event_source.get_events():
            try:
                with self.lock:
                    log.debug(f"EVENT_LOOP: Acquired lock and processing document: {doc.get('src_ip', 'N/A')}")
                    self._process_event(doc)
            except Exception as e:
                # This is a critical catch-all to ensure the event loop thread doesn't die silently.
                log.error(f"EVENT_LOOP: CRITICAL - Unhandled exception in event processing for doc: {doc}", exc_info=True)
    
    def _process_event(self, doc: Dict) -> None:
        """Process a single log event."""
        log.debug(f"EVENT_LOOP-PROCESS: Starting event processing for doc: {doc}")
        # Extract IP and timestamp
        ip = doc.get('src_ip')
        if not ip:
            return
        
        log.info(f"EVENT_LOOP: Processing event for IP: {ip}")

        # Get or create IP profile and update it
        ip_profile = self.connection_tracker.get_or_create_ip_profile(ip)
        ip_profile.update(doc)
        
        now = time.time()
        
        # Extract features using the updated profile
        # Compute capped minutes since last event for this IP
        time_delta_min = 0.0
        if self.last_timestamp[ip] > 0:
            time_delta_min = min((now - self.last_timestamp[ip]) / 60.0, 10.0)

        observation = self.feature_extractor.extract(doc, ip_profile, time_since_last_min=time_delta_min)
        
        # Add to buffer
        self.ip_buffers[ip].append(observation)
        self.last_timestamp[ip] = now
        
        log.info(f"EVENT_LOOP: Buffer size for {ip} is {len(self.ip_buffers[ip])}/{agent_config.sequence_length}")

        # Allow decisions from the first observation onward; pad to sequence_length with zeros
        if len(self.ip_buffers[ip]) < agent_config.sequence_length:
            pad_count = agent_config.sequence_length - len(self.ip_buffers[ip])
            if pad_count > 0:
                zero_obs = np.zeros_like(self.ip_buffers[ip][0]) if len(self.ip_buffers[ip]) > 0 else np.zeros(int(self.feature_extractor.feature_dim))
                padded = list(self.ip_buffers[ip]) + [zero_obs] * pad_count
                state = np.array(padded)
            else:
                state = np.array(self.ip_buffers[ip])
        else:
            state = np.array(self.ip_buffers[ip])
        
        # state tensor prepared above (with padding if needed)

        # Get action from agent
        log.info(f"EVENT_LOOP: Buffer full for {ip}. Getting action from agent...")
        action = self.inference_service.get_action(state)

        # Resource-aware promotion to avoid idle cluster
        try:
            cpu_ratio = float(doc.get('cpu_ratio', 1.0))
            mem_ratio = float(doc.get('mem_ratio', 1.0))
            headroom_ok = max(cpu_ratio, mem_ratio) < 0.6
        except Exception:
            headroom_ok = False
        if action == "wait" and headroom_ok:
            log.debug(f"EVENT_LOOP: Promoting action to 'deploy' due to low cluster utilization.")
            action = "deploy"
        
        log.info(f"EVENT_LOOP: Agent chose action '{action}' for IP {ip}")
        
        # Execute action
        reward = self._execute_action(action, ip, state, now)

        # Finalize previous pending transition with current state as next_state
        if ip in self.pending_transitions:
            prev_state, prev_action, prev_reward, prev_time = self.pending_transitions.pop(ip)
            self.agent.remember(prev_state, prev_action, prev_reward, state, False, ip=ip)
            self.stats['rewards_given'] += 1 if prev_reward != 0 else 0

        # Store current decision as pending (to be completed with next_state on next event)
        self.pending_transitions[ip] = (state.copy(), action, float(reward), now)
        
        # Check for pending deploy rewards
        self._check_pending_deploys(doc, ip, state)
        
        # Update statistics
        self.stats['events_processed'] += 1
        
        # Periodic maintenance
        if self.stats['events_processed'] % 1000 == 0:
            self._periodic_maintenance()
    
    def _execute_action(self, action: str, ip: str, state: np.ndarray, now: float) -> float:
        """Execute the chosen action and return immediate reward."""
        reward = 0.0
        
        if action == "deploy":
            # Check cooldown
            if now - self.last_deploy_time.get(ip, 0) < system_config.ip_cooldown_sec:
                log.info(f"EVENT_LOOP: Cooldown active for {ip}, skipping deploy.")
                reward = feature_config.cooldown_penalty
                self.stats['cooldowns_hit'] += 1
            elif self.honeypod_manager:
                # Check for sufficient cluster resources
                if not self.honeypod_manager.has_sufficient_resources():
                    log.warning(f"EVENT_LOOP: Insufficient resources for {ip}, skipping deploy.")
                    # Use a small penalty to discourage deploying when overloaded
                    reward = feature_config.cooldown_penalty 
                else:
                    log.info(f"EVENT_LOOP: Calling HoneypodManager to deploy for IP {ip}.")
                    # Deploy honeypod
                    success, port_mapping = self.honeypod_manager.deploy_honeypod(ip)
                    if success and port_mapping:
                        self.last_deploy_time[ip] = now
                        self.pending_deploys[ip] = (state.copy(), now)
                        self.stats['deploys_triggered'] += 1
                        log.info(f"EVENT_LOOP: Honeypod deployment reported as SUCCESSFUL for {ip}.")

                        # Get pod IP and port for redirection
                        pod_ip, pod_port = self._get_honeypod_ip_and_port(ip)

                        if pod_ip and pod_port and self.redis_publisher:
                            self.redis_publisher.publish_redirection(
                                attacker_ip=ip,
                                pod_ip=pod_ip,
                                pod_port=pod_port
                            )
                        else:
                            log.warning(f"Could not send redirection for {ip}. "
                                        f"Pod IP/Port: {pod_ip}/{pod_port}, Publisher: {self.redis_publisher is not None}")
                        
                        # Setup connection tracking for all ports
                        self._setup_connection_tracking(ip, port_mapping)
                        
                    else:
                        log.warning(f"EVENT_LOOP: Honeypod deployment reported as FAILED for {ip}.")
            else:
                log.warning("EVENT_LOOP: deploy action chosen, but HoneypodManager is not available.")

        # Do not store here; transition will be finalized when next_state is available
        
        return reward
    
    def _check_pending_deploys(self, doc: Dict, ip: str, current_state: np.ndarray) -> None:
        """Check if this is a honeypod hit for a pending deploy."""
        # Simple heuristic: check if this is marked as a honeypod event
        if doc.get('is_honeypod_hit') and ip in self.pending_deploys:
            deploy_state, deploy_time = self.pending_deploys.pop(ip)

            # If we have a pending transition for this IP, merge the delayed reward
            if ip in self.pending_transitions:
                prev_state, prev_action, prev_reward, prev_time = self.pending_transitions.pop(ip)
                combined_reward = float(prev_reward) + float(feature_config.attack_reward)
                self.agent.remember(prev_state, "deploy", combined_reward, current_state, False, ip=ip)
            else:
                # Fallback: store positive reward transition for deploy
                self.agent.remember(deploy_state, "deploy", float(feature_config.attack_reward), current_state, False, ip=ip)

            self.agent.train_batch(1)  # Immediate training on positive examples
            self.stats['rewards_given'] += 1
            log.info(f"Positive reward for honeypod hit from {ip}")
    
    def _periodic_maintenance(self) -> None:
        """Perform periodic maintenance tasks."""
        log.info(f"Event loop stats: {self.stats}")
        
        # Train agent
        self.agent.train_batch()
        
        # Check for expired deploys
        now = time.time()
        expired = []
        for ip, (state, deploy_time) in self.pending_deploys.items():
            if now - deploy_time > system_config.honeypod_ttl_sec:
                expired.append(ip)
        
        # Penalize expired deploys
        for ip in expired:
            state, _ = self.pending_deploys.pop(ip)
            # Use empty state as "terminal" state for expired deploys
            terminal_state = np.zeros_like(state)
            self.agent.remember(state, "deploy", feature_config.false_deploy_penalty, 
                         terminal_state, True, ip=ip)
            log.debug(f"Expired deploy for {ip}, negative reward")

        # Finalize stale pending transitions (no next event arrived)
        now = time.time()
        expired_ips = []
        for ip, (p_state, p_action, p_reward, p_time) in self.pending_transitions.items():
            if now - p_time > system_config.idle_timeout_sec:
                expired_ips.append(ip)
        for ip in expired_ips:
            p_state, p_action, p_reward, p_time = self.pending_transitions.pop(ip)
            terminal_state = np.zeros_like(p_state)
            self.agent.remember(p_state, p_action, p_reward, terminal_state, True, ip=ip)
        
        # Clean up old honeypods
        if self.honeypod_manager:
            self.honeypod_manager.cleanup_expired_pods(system_config.honeypod_ttl_sec)
        
        # Save model periodically
        if self.stats['events_processed'] % 10000 == 0:
            agent.save()
            save_feature_stats()
    
    def _setup_connection_tracking(self, attacker_ip: str, port_mapping: Dict[str, int]):
        """Setup connection tracking for attacker to honeypod."""
        try:
            # Get pod IP from the honeypod deployment
            pod_ip, _ = self._get_honeypod_ip_and_port(attacker_ip)
            if not pod_ip:
                log.error(f"Failed to get pod IP for attacker {attacker_ip}")
                return

            # Setup connection tracking
            success = self.connection_tracker.setup_connection_tracking(
                attacker_ip, pod_ip, port_mapping
            )
            
            if success:
                log.info(f"Connection tracking established for {attacker_ip} -> {pod_ip}")
            else:
                log.error(f"Failed to setup connection tracking for {attacker_ip}")

        except Exception as e:
            log.error(f"Unexpected error setting up connection tracking for {attacker_ip}: {e}")
    
    def _get_honeypod_ip_and_port(self, attacker_ip: str) -> Tuple[Optional[str], Optional[int]]:
        """Get the pod IP and the first container port for the honeypod serving this attacker."""
        try:
            # Get pods with the label for this attacker IP
            pods = self.k8s_core_api.list_namespaced_pod(
                namespace=self.config.namespace,
                label_selector=f"app=honeypod,src-ip={attacker_ip}"
            ).items

            if pods and pods[0].status.pod_ip:
                pod_ip = pods[0].status.pod_ip
                # Assuming the first container and first port is the one we want
                if pods[0].spec.containers and pods[0].spec.containers[0].ports:
                    pod_port = pods[0].spec.containers[0].ports[0].container_port
                    return pod_ip, pod_port
                else:
                    log.warning(f"Honeypod for {attacker_ip} has no ports defined.")
                    return pod_ip, None
            else:
                log.warning(f"No running honeypod found for {attacker_ip}")
                return None, None

        except Exception as e:
            log.error(f"Failed to get honeypod IP and port for {attacker_ip}: {e}")
            return None, None
    
    def _get_timestamp(self, doc: Dict) -> datetime:
        """Extract timestamp from document."""
        ts_field = doc.get('@timestamp', doc.get('timestamp'))
        if isinstance(ts_field, str):
            # Handle ISO format with 'Z' timezone
            if ts_field.endswith('Z'):
                ts_field = ts_field[:-1] + '+00:00'
            return datetime.fromisoformat(ts_field)
        return datetime.now(timezone.utc)
    
    def _cleanup(self) -> None:
        """Cleanup on exit."""
        log.info("Shutting down event loop")
        agent.save()
        save_feature_stats()
        log.info(f"Final stats: {self.stats}")

    async def process_events_batch(self, docs: List[Dict]) -> None:
        """Process multiple events in parallel for high-scale operation."""
        if not docs:
            return
            
        log.info(f"Processing batch of {len(docs)} events")
        
        # Group events by IP for efficient processing
        ip_events = defaultdict(list)
        for doc in docs:
            src_ip = doc.get('src_ip')
            if src_ip:
                ip_events[src_ip].append(doc)
        
        # Process IPs in parallel batches
        tasks = []
        for batch_start in range(0, len(ip_events), self.config.deployment_batch_size):
            batch_ips = list(ip_events.keys())[batch_start:batch_start + self.config.deployment_batch_size]
            batch_events = {ip: ip_events[ip] for ip in batch_ips}
            task = asyncio.create_task(self._process_ip_batch(batch_events))
            tasks.append(task)
        
        # Wait for all batches to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _process_ip_batch(self, ip_events: Dict[str, List[Dict]]) -> None:
        """Process a batch of IPs efficiently."""
        deployment_tasks = []
        
        for src_ip, events in ip_events.items():
            # Skip if recently processed
            if self._should_skip_ip(src_ip):
                continue
                
            latest_event = max(events, key=lambda x: x.get('@timestamp', ''))

            # Get or create IP profile and update it
            ip_profile = self.connection_tracker.get_or_create_ip_profile(src_ip)
            ip_profile.update(latest_event)  # Update with the most recent event

            features = self.feature_extractor.extract(latest_event, ip_profile)

            # Check if features are valid
            if features.size == 0:
                # Skip this IP if features are invalid
                continue

            # Make RL decision
            action = self.agent.act(features)
            log.debug(f"Action for {src_ip}: {action}")

            # agent.act returns action string ("wait"|"deploy")
            if action == "deploy":
                task = asyncio.create_task(self._deploy_honeypod_async(src_ip, features))
                deployment_tasks.append(task)

            # Update tracking
            self.ip_last_decision[src_ip] = datetime.now(timezone.utc)

        # Execute deployments in parallel with semaphore control
        if deployment_tasks:
            await asyncio.gather(*deployment_tasks, return_exceptions=True)
            
    async def _deploy_honeypod_async(self, src_ip: str, features: Dict) -> None:
        """Deploy honeypod asynchronously with semaphore control."""
        async with self.deployment_semaphore:
            if src_ip in self.active_deployments:
                log.debug(f"Deployment already in progress for {src_ip}")
                return
                
            self.active_deployments.add(src_ip)
            try:
                # Check cluster resources first
                if not self.honeypod_manager.has_sufficient_resources():
                    log.warning(f"Insufficient cluster resources for {src_ip}")
                    return
                    
                # Deploy honeypod
                success, port_mapping = self.honeypod_manager.deploy_honeypod(src_ip)
                
                if success and port_mapping:
                    # Use thread pool for SSH operations to avoid blocking
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        self.ssh_executor,
                        self._setup_sensor_connection_tracking,
                        src_ip,
                        port_mapping
                    )
                    
                    # Store experience for RL training
                    reward = 1.0 if success else -0.1
                    self.agent.remember(features, 1, reward, False)
                    log.info(f"Successfully deployed honeypod for {src_ip}")
                else:
                    log.warning(f"Failed to deploy honeypod for {src_ip}")
                    self.agent.remember(features, 1, -0.5, False)
                    
            except Exception as e:
                log.error(f"Error deploying honeypod for {src_ip}: {e}")
                self.agent.remember(features, 1, -1.0, False)
            finally:
                self.active_deployments.discard(src_ip)
                
    def _setup_sensor_connection_tracking(self, src_ip: str, port_mapping: Dict[str, int]) -> None:
        """Setup sensor connection tracking using SSH (runs in thread pool)."""
        import subprocess
        
        try:
            # Get the primary honeypod IP (first port mapping)
            honeypod_ip = list(port_mapping.keys())[0] if port_mapping else None
            if not honeypod_ip:
                log.error(f"No honeypod IP available for {src_ip}")
                return
                
            # Execute connection tracking script on sensor via SSH
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes",
                "-i", self.config.sensor_ssh_key,
                f"{self.config.sensor_user}@{self.config.sensor_ip}",
                f"~/ADLAH/sensor/setup_connection_tracking.sh {src_ip} {honeypod_ip} {self.config.honeypod_ttl_sec}"
            ]
            
            result = subprocess.run(
                ssh_cmd, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            if result.returncode == 0:
                log.info(f"Sensor redirect configured for {src_ip} -> {honeypod_ip}")
            else:
                log.error(f"Failed to configure sensor redirect for {src_ip}: {result.stderr}")
                
        except Exception as e:
            log.error(f"Error setting up sensor redirect for {src_ip}: {e}")
            
    def _should_skip_ip(self, src_ip: str) -> bool:
        """Check if IP should be skipped based on cooldown and recent decisions."""
        now = datetime.now(timezone.utc)
        
        # Check cooldown period
        if src_ip in self.ip_last_decision:
            time_since_decision = (now - self.ip_last_decision[src_ip]).total_seconds()
            if time_since_decision < self.config.ip_cooldown_sec:
                return True
                
        return False