"""
Kubernetes operations for honeypod deployment and management.
"""
import logging
import time
from typing import Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

from .config import system_config

log = logging.getLogger(__name__)


class HoneypodManager:
    """Manages honeypod deployments in Kubernetes."""
    
    def __init__(self, apps_api: client.AppsV1Api, core_api: client.CoreV1Api):
        self.apps_api = apps_api
        self.core_api = core_api
        self.config = system_config
    
    def deploy_honeypod(self, ip: str) -> tuple[bool, Optional[dict[str, int]], Optional[str]]:
        """Deploy a honeypod and return host port mapping and node IP."""
        name = self._get_pod_name(ip)

        # 1) Fast path: Deployment already exists?
        try:
            if self.apps_api.read_namespaced_deployment(name=name, namespace=self.config.namespace):
                log.info(f"Honeypod deployment {name} already exists, using it.")
                port_mapping, node_ip = self._get_pod_host_ports(ip, timeout=30)
                return (True, port_mapping, node_ip) if port_mapping and node_ip else (False, None, None)
        except ApiException as e:
            if e.status != 404:
                log.warning(f"Could not check for existing deployment: {e}")

        # 2.5) Try to use a pod from the warm pool
        try:
            warm_pods = self.core_api.list_namespaced_pod(
                namespace=self.config.namespace,
                label_selector="app=honeypod-pool,status=ready"
            ).items
            if warm_pods:
                warm_pod = warm_pods[0]
                node_name = warm_pod.spec.node_name
                log.info(f"Using warm pod {warm_pod.metadata.name} for {ip} on node {node_name}")
                
                # Delete the placeholder pod from the pool
                try:
                    self.core_api.delete_namespaced_pod(
                        name=warm_pod.metadata.name,
                        namespace=self.config.namespace,
                        grace_period_seconds=0
                    )
                except ApiException as e:
                    log.warning(f"Could not delete warm pod {warm_pod.metadata.name}: {e}")

                # Create the actual deployment, targeting the same node
                labels = {"app": "honeypod", "src-ip": ip}
                deployment = self._create_deployment_spec(name, ip, labels, node_name=node_name)
                self.apps_api.create_namespaced_deployment(namespace=self.config.namespace, body=deployment)

                port_mapping, node_ip = self._get_pod_host_ports(ip, timeout=120)
                return (True, port_mapping, node_ip) if port_mapping and node_ip else (False, None, None)
        except ApiException as e:
            log.warning(f"Error while trying to use warm pods: {e}")

        # 3) Create a new deployment from scratch
        labels = {"app": "honeypod", "src-ip": ip}
        deployment = self._create_deployment_spec(name, ip, labels)
        try:
            self.apps_api.create_namespaced_deployment(namespace=self.config.namespace, body=deployment)
            log.info(f"Created honeypod deployment {name} for IP {ip}")
            
            port_mapping, node_ip = self._get_pod_host_ports(ip, timeout=300)
            if not port_mapping or not node_ip:
                log.warning(f"Honeypod {name} did not get host ports and a node IP within 300s. No redirect possible.")
                return True, None, None

            log.info(f"Honeypod for {ip} is running on {node_ip} with mapping: {port_mapping}")
            return True, port_mapping, node_ip
        except ApiException as e:
            if e.status == 409:
                log.info(f"Honeypod {name} already exists. Getting its ports...")
                port_mapping, node_ip = self._get_pod_host_ports(ip, timeout=60)
                return (True, port_mapping, node_ip) if port_mapping and node_ip else (False, None, None)
            else:
                log.error(f"Failed to create honeypod {name}: {e}")
                return False, None, None
    
    def delete_honeypod(self, ip: str) -> bool:
        """Delete honeypod deployment for the given IP."""
        name = self._get_pod_name(ip)
        
        try:
            # Delete deployment only (no service needed with hostNetwork)
            self.apps_api.delete_namespaced_deployment(
                name=name,
                namespace=self.config.namespace,
                grace_period_seconds=30
            )
            log.info(f"Deleted honeypod deployment {name}")
            
            return True
            
        except ApiException as e:
            if e.status == 404:
                log.debug(f"Honeypod {name} does not exist")
                return True
            else:
                log.error(f"Failed to delete honeypod {name}: {e}")
                return False
    
    def _get_pod_host_ports(self, ip: str, timeout: float = 60.0) -> tuple[Optional[dict[str, int]], Optional[str]]:
        """Get host port mappings and the node's internal IP for a honeypod."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                pods = self.core_api.list_namespaced_pod(
                    namespace=self.config.namespace,
                    label_selector=f"app=honeypod,src-ip={ip}"
                ).items
                
                if pods:
                    pod = pods[0]
                    if pod.status.phase == 'Running' and pod.spec.containers:
                        ports = {
                            f"{p.container_port}/tcp": p.host_port
                            for c in pod.spec.containers if c.ports
                            for p in c.ports if p.host_port
                        }
                        
                        node_name = pod.spec.node_name
                        if ports and node_name:
                            node_info = self.core_api.read_node(name=node_name)
                            node_ip = next(
                                (addr.address for addr in node_info.status.addresses if addr.type == "InternalIP"),
                                None
                            )
                            if node_ip:
                                return ports, node_ip
                
                log.debug(f"Waiting for pod for IP {ip} to be running and have host ports/node IP...")
                time.sleep(2)
                
            except ApiException as e:
                log.error(f"API error getting pod for IP {ip}: {e}")
                return None, None
        
        log.warning(f"Timeout waiting for pod for IP {ip} to get host ports and node IP.")
        return None, None

    def get_pod_ip(self, ip: str, timeout: float = 30.0) -> Optional[str]:
        """Get the actual pod IP from Kubernetes for a honeypod deployment."""
        name = self._get_pod_name(ip)
        
        # Wait for pod to be ready and get its IP
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                pods = self.core_api.list_namespaced_pod(
                    namespace=self.config.namespace,
                    label_selector=f"app=honeypod,src-ip={ip}"
                ).items
                
                if pods:
                    pod = pods[0]
                    if pod.status.pod_ip and pod.status.phase == 'Running':
                        log.info(f"Found pod IP {pod.status.pod_ip} for honeypod {ip}")
                        return pod.status.pod_ip
                    elif pod.status.phase == 'Pending':
                        log.debug(f"Pod {name} is still pending, waiting...")
                    else:
                        log.debug(f"Pod {name} status: {pod.status.phase}, IP: {pod.status.pod_ip}")
                
                time.sleep(2)
                
            except ApiException as e:
                log.error(f"Failed to get pod IP for {ip}: {e}")
                return None
        
        log.warning(f"Could not get pod IP for honeypod {ip} within {timeout}s timeout")
        return None
    
    def cleanup_expired_pods(self, max_age_seconds: int = 3600) -> None:
        """Delete honeypods older than max_age_seconds."""
        try:
            deployments = self.apps_api.list_namespaced_deployment(
                namespace=self.config.namespace,
                label_selector="app=honeypod"
            ).items
            
            now = time.time()
            
            for deployment in deployments:
                creation_time = deployment.metadata.creation_timestamp.timestamp()
                age_seconds = now - creation_time
                
                if age_seconds > max_age_seconds:
                    name = deployment.metadata.name
                    ip = deployment.metadata.labels.get("src-ip", "unknown")
                    log.info(f"Deleting expired honeypod {name} for IP {ip} (age: {age_seconds:.0f}s)")
                    try:
                        self.apps_api.delete_namespaced_deployment(
                            name=name,
                            namespace=self.config.namespace,
                            grace_period_seconds=30
                        )
                    except ApiException as e:
                        if e.status != 404:
                            log.error(f"Failed to delete expired deployment {name}: {e}")

        except ApiException as e:
            log.error(f"Failed to list deployments for cleanup: {e}")
    
    def _get_node_metrics(self) -> list:
        """Get CPU and memory usage for all nodes."""
        try:
            # Note: This requires the Kubernetes metrics-server to be installed.
            api = client.CustomObjectsApi()
            metrics = api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
            return metrics.get('items', [])
        except ApiException as e:
            log.error(f"Could not fetch node metrics. Is metrics-server installed? Error: {e}")
            return []

    def _parse_resource(self, resource_str: str, resource_type: str) -> int:
        """Parse Kubernetes resource string like '1024Ki', '100m', '0.5' into a base unit."""
        resource_str = str(resource_str)
        
        # Memory units (to bytes)
        if resource_str.endswith("Ki"):
            return int(resource_str[:-2]) * 1024
        if resource_str.endswith("Mi"):
            return int(resource_str[:-2]) * 1024**2
        if resource_str.endswith("Gi"):
            return int(resource_str[:-2]) * 1024**3
        
        # CPU units (to nanocores)
        if resource_str.endswith("n"):
            return int(resource_str[:-1])
        if resource_str.endswith("m"):
            return int(resource_str[:-1]) * 1_000_000
            
        # Plain numbers (cores or bytes)
        try:
            val = float(resource_str)
            if resource_type == 'cpu':
                # For CPU, '1' means 1 core = 1e9 nanocores
                return int(val * 1_000_000_000)
            else:
                # For memory, it's just bytes
                return int(val)
        except ValueError:
            raise ValueError(f"Could not parse resource string: {resource_str}")

    def has_sufficient_resources(self) -> bool:
        """Check if at least one cluster node has enough resources for a new pod."""
        nodes = self._get_node_metrics()
        if not nodes:
            log.warning("Cannot determine cluster resources; assuming sufficient.")
            return True  # Fail open if metrics are unavailable

        for node in nodes:
            try:
                node_name = node['metadata']['name']
                
                # Extract usage and capacity
                usage_cpu = self._parse_resource(node['usage']['cpu'], 'cpu')
                usage_mem = self._parse_resource(node['usage']['memory'], 'mem')

                # To get capacity, we need to describe the node
                node_info = self.core_api.read_node(name=node_name)
                capacity_cpu = self._parse_resource(node_info.status.capacity['cpu'], 'cpu')
                capacity_mem = self._parse_resource(node_info.status.capacity['memory'], 'mem')

                if capacity_cpu == 0 or capacity_mem == 0:
                    log.warning(f"Node {node_name} has zero capacity, skipping.")
                    continue

                # Calculate usage percentage
                cpu_usage_percent = (usage_cpu / capacity_cpu) * 100
                mem_usage_percent = (usage_mem / capacity_mem) * 100
                
                log.debug(f"Node {node_name}: CPU {cpu_usage_percent:.1f}%, Memory {mem_usage_percent:.1f}%")

                # Check against thresholds
                if cpu_usage_percent < self.config.cpu_threshold_percent and \
                   mem_usage_percent < self.config.memory_threshold_percent:
                    log.info(f"Found node with sufficient resources: {node_name}")
                    return True  # At least one node is available
            
            except (KeyError, ValueError, TypeError) as e:
                log.error(f"Could not parse metrics for node {node.get('metadata', {}).get('name', 'unknown')}: {e}")
                continue  # Try next node
        
        log.warning("No nodes with sufficient resources found.")
        return False  # All nodes are over capacity or failed to parse
    
    def _get_pod_name(self, ip: str) -> str:
        """Generate pod name from IP address."""
        return f"honeypod-{ip.replace('.', '-')}"
    
    def _create_deployment_spec(
        self,
        name: str,
        ip: str,
        labels: dict,
        node_name: Optional[str] = None,
    ) -> client.V1Deployment:
        """Create deployment specification for honeypod.

        Wenn node_name angegeben ist, wird der Pod gezielt auf diesem Node
        gestartet (so nutzt er das bereits gecachte Image des Warmhalte-Pods).
        """
        
        # Ports to be exposed by the honeypod container
        # We map them to random host ports by setting host_port=0
        honeypod_ports = [
            client.V1ContainerPort(container_port=21, host_port=0, protocol="TCP"),   # FTP
            client.V1ContainerPort(container_port=22, host_port=0, protocol="TCP"),   # SSH
            client.V1ContainerPort(container_port=23, host_port=0, protocol="TCP"),   # Telnet
            client.V1ContainerPort(container_port=25, host_port=0, protocol="TCP"),   # SMTP
            client.V1ContainerPort(container_port=80, host_port=0, protocol="TCP"),   # HTTP
            client.V1ContainerPort(container_port=443, host_port=0, protocol="TCP"),  # HTTPS
            client.V1ContainerPort(container_port=3306, host_port=0, protocol="TCP"), # MySQL
            client.V1ContainerPort(container_port=5900, host_port=0, protocol="TCP"), # VNC
            client.V1ContainerPort(container_port=8080, host_port=0, protocol="TCP"), # HTTP-Alt
        ]

        cowrie_container = client.V1Container(
            name="cowrie",
            image="cowrie/cowrie:latest",
            env=[client.V1EnvVar(name="SRC_IP", value=ip)],
            ports=honeypod_ports,
            volume_mounts=[
                client.V1VolumeMount(name="cowrie-data", mount_path="/home/cowrie")
            ]
        )
        
        filebeat_container = client.V1Container(
            name="filebeat",
            image="docker.elastic.co/beats/filebeat:8.13.4",
            env=[
                client.V1EnvVar(name="SRC_IP", value=ip),
                client.V1EnvVar(name="HIVE_IP", value=self.config.hive_ip)
            ],
            volume_mounts=[
                client.V1VolumeMount(name="cowrie-data", mount_path="/home/cowrie"),
                client.V1VolumeMount(name="fb-config", mount_path="/etc/filebeat/filebeat.yml", sub_path="filebeat.yml"),
                client.V1VolumeMount(name="fb-ca", mount_path="/etc/certs")
            ]
        )
        
        pod_spec = client.V1PodSpec(
            containers=[cowrie_container, filebeat_container],
            node_name=node_name,
            volumes=[
                client.V1Volume(name="cowrie-data", empty_dir=client.V1EmptyDirVolumeSource()),
                client.V1Volume(name="fb-config", config_map=client.V1ConfigMapVolumeSource(name="filebeat-honeypod")),
                client.V1Volume(name="fb-ca", secret=client.V1SecretVolumeSource(secret_name="filebeat-certs"))
            ]
        )
        
        return client.V1Deployment(
            metadata=client.V1ObjectMeta(name=name, labels=labels),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(match_labels=labels),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels=labels,
                        annotations={"cni.projectcalico.org/ipv4pools": '["honeypod-pool"]'}
                    ),
                    spec=pod_spec
                )
            )
        )
    




def setup_kubernetes(max_retries: int = 15, delay_seconds: int = 10) -> Optional[tuple[client.AppsV1Api, client.CoreV1Api]]:
    """
    Load Kubernetes configuration with retries and return API clients.
    The agent may start before the K8s cluster is fully available.
    """
    for attempt in range(max_retries):
        try:
            # Load the configuration from within the cluster
            config.load_incluster_config()
            log.info("Successfully loaded in-cluster Kubernetes config.")
            
            # Verify connectivity
            core_api = client.CoreV1Api()
            core_api.get_api_resources(timeout_seconds=5)
            
            log.info("Kubernetes API is responsive.")
            return client.AppsV1Api(), core_api

        except Exception as e:
            if attempt < max_retries - 1:
                log.warning(
                    f"K8s config failed (attempt {attempt + 1}/{max_retries}): {e}. "
                    f"Retrying in {delay_seconds} seconds..."
                )
                time.sleep(delay_seconds)
            else:
                log.error(f"FATAL: Could not load K8s config after {max_retries} attempts: {e}")
                return None
    return None
