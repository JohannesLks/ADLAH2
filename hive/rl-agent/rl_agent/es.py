"""
Elasticsearch client for log retrieval and transform management.
"""
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

import json
import redis
from elasticsearch import Elasticsearch, NotFoundError, ConflictError

from .config import system_config

log = logging.getLogger(__name__)


class RedisPublisher:
    """Handles publishing messages to a Redis pub/sub channel."""

    def __init__(self):
        self._client = self._create_client()
        self._channel = "redirection-commands"

    def _create_client(self):
        """Create a Redis client from system config."""
        try:
            log.info(f"Connecting to Redis at: {system_config.redis_host}:{system_config.redis_port}")
            client = redis.Redis(
                host=system_config.redis_host,
                port=system_config.redis_port,
                db=0,
                decode_responses=True
            )
            client.ping()
            return client
        except redis.exceptions.ConnectionError as e:
            log.error(f"Failed to connect to Redis: {e}")
            raise ConnectionError("Could not connect to Redis") from e

    def publish_redirection(self, attacker_ip: str, pod_ip: str, pod_port: int) -> bool:
        """Publish a redirection command as a JSON message."""
        message = {
            "attacker_ip": attacker_ip,
            "pod_ip": pod_ip,
            "pod_port": pod_port
        }
        try:
            json_message = json.dumps(message)
            self._client.publish(self._channel, json_message)
            log.info(f"Published redirection command to '{self._channel}': {json_message}")
            return True
        except redis.exceptions.RedisError as e:
            log.error(f"Failed to publish to Redis channel '{self._channel}': {e}")
        except TypeError as e:
            log.error(f"Failed to serialize message to JSON: {e}")
        return False


class ElasticsearchClient:
    """Wrapper for Elasticsearch operations."""
    
    def __init__(self):
        self.client = self._create_client()
        self.ensure_transform()
    
    def _create_client(self) -> Elasticsearch:
        """Create Elasticsearch client with authentication if configured."""
        auth = None
        if system_config.es_user and system_config.es_pass:
            auth = (system_config.es_user, system_config.es_pass)
        
        log.info(f"Connecting to Elasticsearch at: {system_config.es_host}")
        return Elasticsearch(
            system_config.es_host,
            basic_auth=auth,
            request_timeout=60
        )
    
    def get_recent_logs(self, since: datetime, limit: int = 100) -> List[Dict]:
        """Get recent log entries since the given timestamp."""
        query = {
            "size": limit,
            "sort": [{"@timestamp": "asc"}],
            "query": {
                "range": {
                    "@timestamp": {
                        "gt": since.isoformat()
                    }
                }
            }
        }
        
        result = self.client.search(
            index=system_config.es_index_pattern,
            body=query
        )
        
        return [hit["_source"] for hit in result["hits"]["hits"]]
    
    def count_logs(self, ip: str, since: datetime) -> int:
        """Count logs for a specific IP since timestamp."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": ip}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}}
                    ]
                }
            }
        }
        
        result = self.client.count(
            index=system_config.es_index_pattern,
            body=query
        )
        
        return result["count"]
    
    def ensure_transform(self) -> None:
        """Ensure the required transform exists and is running."""
        transform_id = system_config.transform_id
        
        try:
            # Check if transform exists
            self.client.transform.get_transform(transform_id=transform_id)
            log.info(f"Transform {transform_id} already exists")
        except NotFoundError:
            # Create transform
            self._create_transform()
        
        # Ensure transform is started
        self._start_transform()
    
    def _create_transform(self) -> None:
        """Create the aggregation transform."""
        body = {
            "source": {"index": system_config.transform_src},
            "dest": {"index": system_config.transform_dest},
            "pivot": {
                "group_by": {
                    "src_ip": {"terms": {"field": "src_ip.keyword"}}
                },
                "aggregations": {
                    "hits": {"value_count": {"field": "@timestamp"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}}
                }
            },
            "sync": {
                "time": {
                    "field": "@timestamp",
                    "delay": "60s"
                }
            },
            "frequency": "60s"
        }
        
        self.client.transform.put_transform(
            transform_id=system_config.transform_id,
            body=body,
            defer_validation=True
        )
        log.info(f"Created transform {system_config.transform_id}")
    
    def _start_transform(self) -> None:
        """Start the transform if not already running."""
        max_wait = 600  # 10 minutes
        wait_interval = 10
        waited = 0
        
        while waited < max_wait:
            try:
                self.client.transform.start_transform(
                    transform_id=system_config.transform_id
                )
                log.info(f"Started transform {system_config.transform_id}")
                return
            except ConflictError:
                log.info(f"Transform {system_config.transform_id} already running")
                return
            except Exception as e:
                if "source index" in str(e):
                    log.info(f"Waiting for source index, retrying in {wait_interval}s...")
                    time.sleep(wait_interval)
                    waited += wait_interval
                else:
                    raise
        
        log.error(f"Failed to start transform after {max_wait}s")


def create_es_client() -> ElasticsearchClient:
    """Create and return Elasticsearch client."""
    for i in range(5):
        try:
            return ElasticsearchClient()
        except Exception as e:
            log.warning(f"Failed to connect to Elasticsearch (attempt {i+1}/5): {e}")
            time.sleep(5)
    log.error("Failed to connect to Elasticsearch after multiple retries")
    raise ConnectionError("Could not connect to Elasticsearch")