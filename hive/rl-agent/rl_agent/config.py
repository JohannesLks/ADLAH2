"""
Unified configuration for the RL Agent system.
All settings can be overridden via environment variables.
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AgentConfig:
    """RL Agent hyperparameters and settings."""
    # Learning parameters
    learning_rate: float = float(os.getenv("RL_LR", "0.001"))
    gamma: float = float(os.getenv("RL_GAMMA", "0.95"))
    epsilon: float = float(os.getenv("RL_EPSILON", "0.05"))
    epsilon_min: float = float(os.getenv("RL_EPSILON_MIN", "0.01"))
    epsilon_decay: float = float(os.getenv("RL_EPSILON_DECAY", "0.995"))
    
    # Memory settings
    batch_size: int = int(os.getenv("RL_BATCH_SIZE", "32"))
    memory_size: int = int(os.getenv("RL_MEMORY_SIZE", "10000"))
    target_update_freq: int = int(os.getenv("RL_TARGET_UPDATE", "10"))
    train_iterations: int = int(os.getenv("RL_TRAIN_ITERS", "3"))
    
    # Model architecture
    sequence_length: int = int(os.getenv("RL_SEQUENCE_LENGTH", "10"))
    lstm_units: int = int(os.getenv("LSTM_UNITS", "64"))
    dense_units: int = int(os.getenv("DENSE_UNITS", "64"))
    dropout_rate: float = float(os.getenv("DROPOUT_RATE", "0.2"))
    
    # Persistence
    cache_dir: Path = Path(os.getenv("RL_CACHE_DIR", os.path.expanduser("~/.cache/rl_agent")))
    model_path: Path = field(init=False)
    memory_path: Path = field(init=False)
    
    def __post_init__(self):
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = self.cache_dir / "rl_policy.keras"
        self.memory_path = self.cache_dir / "replay_memory.pkl"


@dataclass
class SystemConfig:
    """System-wide settings for deployment and operation."""
    # Kubernetes
    namespace: str = os.getenv("HONEYPOD_NS", "honeypod")
    honeypod_ttl_sec: int = int(os.getenv("HONEYPOD_TTL_SEC", "1800"))
    ip_cooldown_sec: int = int(os.getenv("IP_COOLDOWN_SEC", "0"))
    cpu_threshold_percent: float = float(os.getenv("CPU_THRESHOLD_PERCENT", "80.0"))
    memory_threshold_percent: float = float(os.getenv("MEMORY_THRESHOLD_PERCENT", "80.0"))
    
    # Sensor SSH config
    sensor_ip: str = os.getenv("SENSOR_IP")
    sensor_user: str = os.getenv("SENSOR_USER")
    sensor_ssh_key: str = os.getenv("SENSOR_SSH_KEY", "/app/secrets/id_rsa")
    hive_ip: str = os.getenv("HIVE_IP")
    
    # Elasticsearch
    es_host: str = os.getenv("ES_HOST", "http://elasticsearch:9200")
    es_user: str = os.getenv("ES_USER", "")
    es_pass: str = os.getenv("ES_PASS", "")
    es_index_pattern: str = os.getenv("ES_LOG_INDEX", "madcat-*")
    es_poll_interval: float = float(os.getenv("ES_POLL_INTERVAL", "1.0"))
    es_batch_size: int = int(os.getenv("ES_BATCH_SIZE", "500"))
    
    # Transform settings
    transform_id: str = os.getenv("TRANSFORM_ID", "madcat_window5")
    transform_src: str = os.getenv("TRANSFORM_SRC", "madcat-*")
    transform_dest: str = os.getenv("TRANSFORM_DEST", "features_madcat")
    
    # Timing
    window_sec: int = int(os.getenv("WINDOW_SEC", "300"))
    idle_timeout_sec: int = int(os.getenv("TIMEOUT_SEC", "300"))
    maintenance_interval_sec: int = int(os.getenv("MAINTENANCE_INTERVAL_SEC", "60"))

    # Deployment concurrency and batching
    max_concurrent_deployments: int = int(os.getenv("MAX_CONCURRENT_DEPLOYS", "8"))
    deployment_batch_size: int = int(os.getenv("DEPLOYMENT_BATCH_SIZE", "32"))
    ssh_connection_pool_size: int = int(os.getenv("SSH_CONNECTION_POOL_SIZE", "16"))


@dataclass
class FeatureConfig:
    """Feature extraction and processing settings."""
    # Hash buckets for categorical features
    hash_buckets: Dict[str, int] = field(default_factory=lambda: {
        "src_ip": 2**20,
        "dest_ip": 2**20,
        "asn": 2**16
    })
    
    # Embedding sizes
    embed_sizes: Dict[str, int] = field(default_factory=lambda: {
        "src_ip": 32,
        "dest_ip": 32,
        "src_port": 8,
        "dest_port": 8,
        "proto": 4,
        "icmp_typecode": 4,
        "country": 8,
        "asn": 16,
        "cluster": 8,
    })
    
    # Normalization
    norm_clip_value: float = 3.0
    
    # Rewards
    attack_reward: float = 1.0
    false_deploy_penalty: float = -0.1
    cooldown_penalty: float = -0.01
    
    # Feature flags
    include_cluster_load: bool = os.getenv("INCLUDE_CLUSTER_LOAD", "1") not in {"0", "false", "False"}
    include_trend_feature: bool = os.getenv("INCLUDE_TREND", "1") not in {"0", "false", "False"}
    include_honeypod_status: bool = os.getenv("INCLUDE_POD_STATUS", "1") not in {"0", "false", "False"}


@dataclass
class InferenceConfig:
    """Inference service batching settings."""
    max_batch_size: int = int(os.getenv("INFERENCE_MAX_BATCH", "32"))
    max_wait_ms: float = float(os.getenv("INFERENCE_MAX_WAIT_MS", "10"))
    timeout_ms: float = float(os.getenv("INFERENCE_TIMEOUT_MS", "2000"))


# Global config instances
agent_config = AgentConfig()
system_config = SystemConfig()
feature_config = FeatureConfig()
inference_config = InferenceConfig()