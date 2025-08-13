#!/usr/bin/env python3
"""
Interactive simulation runner for the RL Agent.

This script runs a continuous simulation loop, generating synthetic log data
to train and evaluate the RL agent in a containerized environment.
"""
import logging
import time
import random
import numpy as np
from collections import deque

from rl_agent.agent import agent
from rl_agent.config import agent_config
from rl_agent.features import extract_features
from rl_agent.logging_setup import setup_logging

log = logging.getLogger(__name__)

class SimulationEngine:
    """Generates synthetic log events for simulation."""

    def __init__(self):
        self.attack_ips = [f"10.0.0.{i}" for i in range(1, 11)]  # 10 persistent attackers
        self.normal_ips = [f"192.168.1.{i}" for i in range(1, 101)] # 100 normal users
        log.info(f"Simulation engine initialized with {len(self.attack_ips)} attackers and {len(self.normal_ips)} normal IPs.")

    def _create_base_event(self, ip: str, is_attack: bool) -> dict:
        """Creates a base event dictionary."""
        return {
            "src_ip": ip,
            "is_attack": is_attack,
            "bytes_in": random.randint(50, 1500),
            "bytes_out": random.randint(50, 5000),
            "proto": 6, # TCP
        }

    def generate_event(self) -> dict:
        """Generates a single log event, simulating normal or attack traffic."""
        if random.random() < 0.2: # 20% chance of an attack event
            ip = random.choice(self.attack_ips)
            event = self._create_base_event(ip, is_attack=True)
            event["hits"] = random.randint(5, 50) # Attacks have more "hits"
            event["is_attack"] = True
        else:
            ip = random.choice(self.normal_ips)
            event = self._create_base_event(ip, is_attack=False)
            event["hits"] = random.randint(1, 5)
            event["is_attack"] = False
        
        return event

def run_simulation():
    """Main simulation loop."""
    setup_logging("INFO")
    log.info("Starting RL Agent simulation runner...")

    engine = SimulationEngine()
    ip_buffers = {}
    last_action_log = time.time()
    
    # Load existing model if available
    agent.load()

    while True:
        try:
            event = engine.generate_event()
            ip = event['src_ip']
            
            observation = extract_features(event)

            if ip not in ip_buffers:
                ip_buffers[ip] = deque(maxlen=agent_config.sequence_length)
            
            ip_buffers[ip].append(observation)

            if len(ip_buffers[ip]) < agent_config.sequence_length:
                continue

            state = np.array(list(ip_buffers[ip]))
            action = agent.act(state)

            reward = 0
            if action == "deploy":
                if event["is_attack"]:
                    reward = 1.0
                    log.info(f"Correctly deployed for attacking IP: {ip}. Reward: {reward}")
                else:
                    reward = -1.0 # Penalize more for wrong deployments
                    log.warning(f"Incorrectly deployed for normal IP: {ip}. Reward: {reward}")
            else: # action == "ignore"
                if event["is_attack"]:
                    reward = -0.5 # Penalize for missing an attack
                    log.warning(f"Missed attack from IP: {ip}. Reward: {reward}")
                else:
                    reward = 0.1 # Small reward for correctly ignoring normal traffic
            
            agent.remember(state, action, reward, state, False, ip=ip)
            
            # Periodically train and save the model
            if agent.is_ready_for_training():
                log.info("Training batch...")
                agent.train_batch(32)
                agent.save()

            if time.time() - last_action_log > 5:
                log.info(f"Processed IP: {ip}, Action: {action}, Epsilon: {agent.epsilon:.4f}")
                last_action_log = time.time()

            time.sleep(random.uniform(0.05, 0.2))

        except KeyboardInterrupt:
            log.info("Simulation stopped by user. Saving final model...")
            agent.save()
            break
        except Exception as e:
            log.error(f"An error occurred in the simulation loop: {e}", exc_info=True)
            time.sleep(5)

if __name__ == "__main__":
    run_simulation() 