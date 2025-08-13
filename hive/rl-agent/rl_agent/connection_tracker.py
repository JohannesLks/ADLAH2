"""
Connection Tracking for RL-Agent
Handles dynamic connection tracking and port multiplexing for honeypod deployments.
"""
import logging
import json
import redis
from typing import Dict, Optional, List, Set
from datetime import datetime, timezone, timedelta
from collections import deque
import time

from .config import system_config

log = logging.getLogger(__name__)

class IPProfile:
    """Represents a behavioral profile for a source IP address, including short-term history."""
    
    def __init__(self, ip_address: str, history_window_seconds: int = 300):
        self.ip_address = ip_address
        self.history_window = timedelta(seconds=history_window_seconds)
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.total_flows: int = 0
        
        # Stores (timestamp, event_data_dict) tuples
        self.events: deque = deque()

    def _prune_old_events(self):
        """Remove events older than the history window."""
        now = datetime.now(timezone.utc)
        while self.events and (now - self.events[0][0] > self.history_window):
            self.events.popleft()

    def update(self, doc: Dict):
        """Update the profile with a new log document."""
        now_ts = time.time()
        now_dt = datetime.now(timezone.utc)
        
        self.last_seen = now_ts
        self.total_flows += 1
        
        # Extract relevant data for historical analysis
        event_data = {
            "dest_port": doc.get("dest_port"),
            "proto": doc.get("refined_proto", doc.get("proto")),
            "dest_ip": doc.get("dest_ip"),
            "is_syn": doc.get("syn", False) and not doc.get("ack", False),
            "is_tcp": doc.get("proto", "").lower() == "tcp",
        }
        
        self.events.append((now_dt, event_data))
        self._prune_old_events()

    def get_historical_features(self) -> Dict[str, float]:
        """Calculate features based on the 5-minute rolling window."""
        self._prune_old_events()
        
        if not self.events:
            return {
                "ev_5m": 0.0, "ports_5m": 0.0, "protos_5m": 0.0,
                "targets_5m": 0.0, "syn_ratio_5m": 0.0
            }

        ports = set(ev["dest_port"] for _, ev in self.events if ev["dest_port"] is not None)
        protos = set(ev["proto"] for _, ev in self.events if ev["proto"] is not None)
        targets = set(ev["dest_ip"] for _, ev in self.events if ev["dest_ip"] is not None)
        
        tcp_packets = [ev for _, ev in self.events if ev["is_tcp"]]
        syn_packets = [ev for ev in tcp_packets if ev["is_syn"]]
        
        syn_ratio = len(syn_packets) / len(tcp_packets) if tcp_packets else 0.0
        
        return {
            "ev_5m": float(len(self.events)),
            "ports_5m": float(len(ports)),
            "protos_5m": float(len(protos)),
            "targets_5m": float(len(targets)),
            "syn_ratio_5m": syn_ratio,
        }

    def to_dict(self) -> Dict:
        """Serialize profile summary to a dictionary."""
        historical_features = self.get_historical_features()
        return {
            "ip_address": self.ip_address,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_flows": self.total_flows,
            "active_window_events": len(self.events),
            **historical_features
        }


class ConnectionTracker:
    """Manages connection tracking for RL-agent deployments."""
    
    def __init__(self):
        self.config = system_config
        
        # Redis connection for connection tracking
        self.redis_client = None
        self.redis_channel = "connection-tracking"
        
        # Active connections tracking
        self.active_connections: Dict[str, Dict] = {}
        self.ip_profiles: Dict[str, IPProfile] = {}
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self) -> None:
        """Initialize Redis connection for connection tracking."""
        try:
            redis_host = getattr(self.config, 'redis_host', 'redis-service.wireguard.svc.cluster.local')
            redis_port = getattr(self.config, 'redis_port', 6379)
            
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            
            # Test connection
            self.redis_client.ping()
            log.info(f"Connection tracking Redis connection established: {redis_host}:{redis_port}")
            
        except Exception as e:
            log.error(f"Failed to connect to Redis for connection tracking: {e}")
            self.redis_client = None
    
    def setup_connection_tracking(self, attacker_ip: str, pod_ip: str, 
                                port_mapping: Dict[str, int]) -> bool:
        """Setup connection tracking for an attacker to honeypod."""
        log.info(f"Setting up connection tracking for attacker {attacker_ip} to pod {pod_ip} with port mapping {port_mapping}")
        
        try:
            # Store connection information
            connection_info = {
                "attacker_ip": attacker_ip,
                "pod_ip": pod_ip,
                "port_mapping": port_mapping,
                "created_at": datetime.now(timezone.utc),
                "status": "active"
            }
            
            self.active_connections[attacker_ip] = connection_info
            
            # Send command to sensor to setup connection tracking
            tracking_info = {
                "action": "track_all_ports",
                "attacker_ip": attacker_ip,
                "pod_ip": pod_ip,
                "port_mapping": port_mapping,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Publish to Redis for sensor consumption
            if self.redis_client:
                self.redis_client.publish("sensor-connection-tracking", json.dumps(tracking_info))
                log.info(f"Connection tracking enabled for attacker {attacker_ip} -> {pod_ip} with port mapping {port_mapping}")
                return True
            else:
                log.error("Redis client not available for connection tracking")
                return False
                
        except Exception as e:
            log.error(f"Failed to setup connection tracking for {attacker_ip}: {e}")
            return False
    
    def cleanup_connection_tracking(self, attacker_ip: str) -> bool:
        """Clean up connection tracking for an attacker."""
        if attacker_ip not in self.active_connections:
            log.warning(f"No active connection tracking found for attacker {attacker_ip}. No cleanup needed.")
            return True
        
        connection_info = self.active_connections[attacker_ip]
        pod_ip = connection_info["pod_ip"]
        
        log.info(f"Cleaning up connection tracking for {attacker_ip}")
        
        try:
            # Send cleanup command to sensor
            cleanup_info = {
                "action": "cleanup_tracking",
                "attacker_ip": attacker_ip,
                "pod_ip": pod_ip,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            if self.redis_client:
                self.redis_client.publish("sensor-connection-tracking", json.dumps(cleanup_info))
                log.info(f"Connection tracking cleanup requested for attacker {attacker_ip} with pod {pod_ip}")
            
            # Remove from tracking
            del self.active_connections[attacker_ip]
            
            log.info(f"Connection tracking cleanup completed for attacker {attacker_ip} with pod {pod_ip}")
            return True
            
        except Exception as e:
            log.error(f"Failed to cleanup connection tracking for {attacker_ip}: {e}")
            return False
    
    def get_connection_status(self, attacker_ip: str) -> Optional[Dict]:
        """Get status of connection tracking for an attacker."""
        return self.active_connections.get(attacker_ip)

    def get_or_create_ip_profile(self, ip_address: str) -> IPProfile:
        """Get or create a behavioral profile for an IP address."""
        if ip_address not in self.ip_profiles:
            self.ip_profiles[ip_address] = IPProfile(ip_address)
        return self.ip_profiles[ip_address]
    
    def list_active_connections(self) -> List[Dict]:
        """List all active connection trackings."""
        return list(self.active_connections.values())
    
    def periodic_cleanup(self, ttl_seconds: int = 1800) -> None:
        """Perform periodic cleanup of expired connections."""
        current_time = datetime.now(timezone.utc)
        expired_attackers = []
        
        for attacker_ip, connection_info in self.active_connections.items():
            created_at = connection_info["created_at"]
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            
            age_seconds = (current_time - created_at).total_seconds()
            if age_seconds > ttl_seconds:
                expired_attackers.append(attacker_ip)
        
        for attacker_ip in expired_attackers:
            log.info(f"Cleaning up expired connection tracking for {attacker_ip}")
            self.cleanup_connection_tracking(attacker_ip)
    
    def get_stats(self) -> Dict:
        """Get connection tracking statistics."""
        return {
            "active_connections": len(self.active_connections),
            "redis_connected": self.redis_client is not None,
            "connections": list(self.active_connections.keys()),
            "profiled_ips": len(self.ip_profiles),
        }