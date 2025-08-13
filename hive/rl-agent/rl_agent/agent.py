"""
Deep Q-Learning Agent with LSTM for sequence modeling.
"""
import logging
import pickle
import random
import threading
from collections import deque
from pathlib import Path
from typing import Deque, Tuple, Optional

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, optimizers

from .config import agent_config, feature_config
from .features import get_feature_dim

log = logging.getLogger(__name__)

ACTIONS = ["wait", "deploy"]


class ReplayMemory:
    """Simple replay buffer for experience replay."""
    
    def __init__(self, capacity: int):
        self.memory: Deque[Tuple] = deque(maxlen=capacity)
    
    def push(self, state: np.ndarray, action: int, reward: float, 
             next_state: np.ndarray, done: bool, **kwargs):
        """Store experience in memory."""
        self.memory.append((state, action, reward, next_state, done, kwargs))
    
    def sample(self, batch_size: int) -> Tuple[np.ndarray, ...]:
        """Sample a batch of experiences."""
        batch = random.sample(self.memory, batch_size)
        states, actions, rewards, next_states, dones, _ = zip(*batch)
        return (
            np.array(states),
            np.array(actions),
            np.array(rewards),
            np.array(next_states),
            np.array(dones)
        )
    
    def __len__(self) -> int:
        return len(self.memory)
    
    def save(self, path: Path) -> None:
        """Save memory to disk."""
        with open(path, 'wb') as f:
            pickle.dump(list(self.memory), f, protocol=4)
        log.info(f"Saved {len(self)} experiences to {path}")
    
    def load(self, path: Path) -> None:
        """Load memory from disk."""
        if path.exists():
            try:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                    self.memory.clear()
                    self.memory.extend(data[:self.memory.maxlen])
                log.info(f"Loaded {len(self)} experiences from {path}")
            except Exception as e:
                log.error(f"Failed to load replay memory: {e}")


class DQNAgent:
    """Deep Q-Network agent using LSTM for temporal modeling."""
    
    def __init__(self):
        self.config = agent_config
        self.feature_dim = get_feature_dim()
        self.action_size = len(ACTIONS)
        
        # Learning parameters
        # Increase exploration defaults for live learning
        self.epsilon = max(self.config.epsilon, 0.2)
        self.epsilon_min = max(self.config.epsilon_min, 0.05)
        self.epsilon_decay = min(self.config.epsilon_decay, 0.999)
        
        # Replay memory
        self.memory = ReplayMemory(self.config.memory_size)
        
        # Neural networks
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
        
        # Training state
        self.train_steps = 0
        
        # Thread safety
        self._model_lock = threading.Lock()
        
    def is_ready_for_training(self) -> bool:
        """Check if there is enough data in memory to start training."""
        return len(self.memory) >= self.config.batch_size

    def _build_model(self) -> keras.Model:
        """Build LSTM-based Dueling Q-network with Huber loss and gradient clipping."""
        inputs = layers.Input(shape=(self.config.sequence_length, self.feature_dim))

        # Mask (in case of variable-length sequences with zero-padding)
        x = layers.Masking(mask_value=0.0)(inputs)

        # Temporal encoder (LSTM kept minimal for seq_len=2)
        x = layers.LSTM(
            self.config.lstm_units,
            return_sequences=False,
            kernel_regularizer=keras.regularizers.l2(0.01)
        )(x)

        x = layers.BatchNormalization()(x)
        x = layers.Dense(self.config.dense_units, activation='relu')(x)
        x = layers.Dropout(self.config.dropout_rate)(x)

        # Dueling head: Value and Advantage streams
        value_stream = layers.Dense(self.config.dense_units, activation='relu')(x)
        value = layers.Dense(1, activation='linear', name='value')(value_stream)

        adv_stream = layers.Dense(self.config.dense_units, activation='relu')(x)
        advantage = layers.Dense(self.action_size, activation='linear', name='advantage')(adv_stream)

        # Combine: Q = V + (A - mean(A))
        advantage_mean = layers.Lambda(lambda a: tf.reduce_mean(a, axis=1, keepdims=True))(advantage)
        advantage_centered = layers.Subtract()([advantage, advantage_mean])
        q_values = layers.Add(name='q_values')([value, advantage_centered])

        model = models.Model(inputs=inputs, outputs=q_values)
        model.compile(
            optimizer=optimizers.Adam(learning_rate=self.config.learning_rate, clipnorm=10.0),
            loss=tf.keras.losses.Huber()
        )

        return model
    
    def update_target_model(self) -> None:
        """Copy weights from main model to target model."""
        self.target_model.set_weights(self.model.get_weights())
    
    def act(self, state: np.ndarray) -> str:
        """Choose action using epsilon-greedy policy."""
        # Check for force deploy mode
        import os
        if os.getenv("FORCE_DEPLOY_ONLY", "0") == "1":
            log.info("FORCE_DEPLOY_ONLY mode: always choosing 'deploy' action")
            return "deploy"
        
        if random.random() <= self.epsilon:
            action_idx = random.randrange(self.action_size)
            log.debug(f"Exploration: {ACTIONS[action_idx]}")
            return ACTIONS[action_idx]
        
        # Reshape for model input
        state_input = state.reshape(1, self.config.sequence_length, self.feature_dim)
        
        with self._model_lock:
            q_values = self.model.predict(state_input, verbose=0)
        
        action_idx = np.argmax(q_values[0])
        log.debug(f"Exploitation: {ACTIONS[action_idx]} (Q={q_values[0][action_idx]:.3f})")
        return ACTIONS[action_idx]
    
    def remember(self, state: np.ndarray, action: str, reward: float,
                 next_state: np.ndarray, done: bool, **kwargs) -> None:
        """Store experience in replay memory."""
        action_idx = ACTIONS.index(action)
        self.memory.push(state, action_idx, reward, next_state, done, **kwargs)
        log.debug(f"Stored experience: action={action}, reward={reward:.3f}, done={done}")
    
    def replay(self) -> None:
        """Train the agent using experience replay (Double DQN targets)."""
        if len(self.memory) < self.config.batch_size:
            return

        # Sample batch
        states, actions, rewards, next_states, dones = self.memory.sample(self.config.batch_size)
        dones = dones.astype(np.float32)

        with self._model_lock:
            # Online network selects best next actions
            online_q_next = self.model.predict(next_states, verbose=0)
            best_next_actions = np.argmax(online_q_next, axis=1)

            # Target network evaluates those actions
            target_q_next_all = self.target_model.predict(next_states, verbose=0)
            target_q_next = target_q_next_all[np.arange(len(best_next_actions)), best_next_actions]

            # Bellman targets
            targets = rewards + self.config.gamma * target_q_next * (1.0 - dones)

            # Current Qs and update only taken actions
            q_values = self.model.predict(states, verbose=0)
            for i, action_idx in enumerate(actions):
                q_values[i, action_idx] = targets[i]

            # Train
            loss = self.model.train_on_batch(states, q_values)
            log.debug(f"Training step {self.train_steps}: loss={float(loss):.4f}")

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        # Update target network
        self.train_steps += 1
        if self.train_steps % max(self.config.target_update_freq, 500) == 0:
            self.update_target_model()
            log.debug("Updated target model")
    
    def load(self) -> None:
        """Load model and replay memory."""
        self._load_model()
        self.memory.load(self.config.memory_path)
    
    def save(self) -> None:
        """Save model and replay memory."""
        self._save_model()
    
    def _save_model(self) -> None:
        """Save model weights (HDF5)."""
        try:
            weight_path = self.config.model_path.with_suffix('.weights.h5')
            self.model.save_weights(str(weight_path), overwrite=True)
            log.info(f"Saved model weights to {weight_path}")
        except Exception as e:
            log.error(f"Failed to save model weights: {e}")
    
    def _load_model(self) -> None:
        """Load model weights if available."""
        weight_path = self.config.model_path.with_suffix('.weights.h5')
        if weight_path.exists():
            try:
                self.model.load_weights(str(weight_path))
                self.update_target_model()
                log.info(f"Loaded model weights from {weight_path}")
            except Exception as e:
                log.warning(f"Could not load model weights: {e}")
    
    def train_batch(self, num_iterations: Optional[int] = None) -> None:
        """Train for multiple iterations."""
        iterations = num_iterations or self.config.train_iterations
        for _ in range(iterations):
            if len(self.memory) >= self.config.batch_size:
                self.replay()


# Global agent instance
agent = DQNAgent()