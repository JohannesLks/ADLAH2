#!/usr/bin/env python3
"""
Offline simulation for testing the RL agent with CSV data.
"""
import argparse
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from tqdm import tqdm

from .config import agent_config
from .features import extract_features, save_feature_stats
from .agent import agent
from .logging_setup import setup_logging

log = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Simulate RL agent with CSV data")
    parser.add_argument("csv_file", type=Path, help="Path to CSV file with log data")
    parser.add_argument("--limit", type=int, help="Limit number of rows to process")
    parser.add_argument("--shuffle", action="store_true", help="Shuffle data before processing")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser.parse_args()


def load_data(csv_path: Path, limit: Optional[int] = None, shuffle: bool = False) -> pd.DataFrame:
    """Load and preprocess CSV data."""
    log.info(f"Loading data from {csv_path}")
    
    # Read CSV
    df = pd.read_csv(csv_path, low_memory=False)
    log.info(f"Loaded {len(df)} rows")
    
    # Parse timestamp if present
    if '@timestamp' in df.columns:
        df['@timestamp'] = pd.to_datetime(df['@timestamp'])
        df = df.sort_values('@timestamp')
    
    # Shuffle if requested
    if shuffle:
        df = df.sample(frac=1.0).reset_index(drop=True)
        log.info("Data shuffled")
    
    # Limit rows if requested
    if limit:
        df = df.head(limit)
        log.info(f"Limited to {len(df)} rows")
    
    return df


def simulate(df: pd.DataFrame) -> dict:
    """Run simulation on dataframe."""
    log.info("Starting simulation")
    
    # Statistics
    stats = {
        'total_events': len(df),
        'unique_ips': df['src_ip'].nunique(),
        'actions': Counter(),
        'rewards': [],
        'deployments': set(),
        'true_positives': 0,
        'false_positives': 0
    }
    
    # Per-IP buffers
    ip_buffers = {}
    
    # Process events
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing events"):
        doc = row.to_dict()
        ip = doc.get('src_ip')
        
        if not ip:
            continue
        
        # Get timestamp
        timestamp = doc.get('@timestamp', datetime.now())
        if pd.isna(timestamp):
            timestamp = datetime.now()
        
        # Extract features
        observation = extract_features(doc, timestamp)
        
        # Initialize buffer for new IPs
        if ip not in ip_buffers:
            ip_buffers[ip] = []
        
        # Add to buffer
        ip_buffers[ip].append(observation)
        
        # Keep only recent observations
        if len(ip_buffers[ip]) > agent_config.sequence_length:
            ip_buffers[ip] = ip_buffers[ip][-agent_config.sequence_length:]
        
        # Need full sequence for decision
        if len(ip_buffers[ip]) < agent_config.sequence_length:
            continue
        
        # Create state
        state = np.array(ip_buffers[ip])
        
        # Get action
        action = agent.act(state)
        stats['actions'][action] += 1
        
        # Simulate deployment
        if action == "deploy" and ip not in stats['deployments']:
            stats['deployments'].add(ip)
            
            # Check if this was correct (simple heuristic)
            is_attack = doc.get('is_attack', False) or doc.get('hits', 0) > 10
            
            if is_attack:
                reward = 1.0
                stats['true_positives'] += 1
            else:
                reward = -0.1
                stats['false_positives'] += 1
            
            # Store experience
            # Use same state as next_state for simulation
            agent.remember(state, action, reward, state, False, ip=ip)
            stats['rewards'].append(reward)
        
        # Train periodically
        if idx % 100 == 0 and idx > 0:
            agent.train_batch(1)
    
    # Final training
    log.info("Final training batch")
    agent.train_batch(10)
    
    return stats


def print_results(stats: dict) -> None:
    """Print simulation results."""
    print("\n" + "="*60)
    print("SIMULATION RESULTS")
    print("="*60)
    print(f"Total events processed: {stats['total_events']:,}")
    print(f"Unique IPs: {stats['unique_ips']:,}")
    print(f"\nActions taken:")
    for action, count in stats['actions'].items():
        pct = count / sum(stats['actions'].values()) * 100
        print(f"  {action}: {count:,} ({pct:.1f}%)")
    
    print(f"\nDeployments: {len(stats['deployments']):,}")
    print(f"  True positives: {stats['true_positives']:,}")
    print(f"  False positives: {stats['false_positives']:,}")
    
    if stats['deployments']:
        precision = stats['true_positives'] / len(stats['deployments'])
        print(f"  Precision: {precision:.2%}")
    
    if stats['rewards']:
        avg_reward = np.mean(stats['rewards'])
        print(f"\nAverage reward: {avg_reward:.3f}")
    
    print(f"\nFinal epsilon: {agent.epsilon:.3f}")


def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(args.log_level)
    
    # Check file exists
    if not args.csv_file.exists():
        log.error(f"CSV file not found: {args.csv_file}")
        return 1
    
    # Load data
    df = load_data(args.csv_file, args.limit, args.shuffle)
    
    # Run simulation
    stats = simulate(df)
    
    # Print results
    print_results(stats)
    
    # Save model and stats
    agent.save()
    save_feature_stats()
    log.info("Model and statistics saved")
    
    return 0


if __name__ == "__main__":
    exit(main())