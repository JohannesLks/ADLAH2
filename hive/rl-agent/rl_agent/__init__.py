"""
ADLAH RL-Agent Package
"""
__version__ = "2.0.0"

from .logging_setup import setup_logging
setup_logging()

from .agent import DQNAgent
from .event_loop import EventLoop, ElasticsearchEventSource
from .k8s import HoneypodManager
from .es import ElasticsearchClient
from .features import extract_features, save_feature_stats

__all__ = [
    "DQNAgent",
    "EventLoop",
    "ElasticsearchEventSource",
    "HoneypodManager",
    "ElasticsearchClient",
    "extract_features",
    "save_feature_stats",
    "setup_logging"
]