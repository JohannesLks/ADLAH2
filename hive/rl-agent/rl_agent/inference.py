"""
Batched inference service for efficient prediction serving.
"""
import logging
import queue
import random
import threading
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from .config import inference_config
from .agent import ACTIONS, DQNAgent

log = logging.getLogger(__name__)


@dataclass
class InferenceRequest:
    """Request for action inference."""
    state: np.ndarray
    response_queue: queue.Queue
    metadata: dict


class InferenceService:
    """Batched inference service for the RL agent."""
    
    def __init__(self, agent: DQNAgent):
        self.agent = agent
        self.config = inference_config
        self.request_queue: queue.Queue[InferenceRequest] = queue.Queue()
        
        # Start worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
        log.info("Inference service started")
    
    def get_action(self, state: np.ndarray, timeout: Optional[float] = None) -> str:
        """Get action for state with timeout."""
        timeout = timeout or self.config.timeout_ms / 1000.0
        response_queue: queue.Queue[str] = queue.Queue(maxsize=1)
        
        request = InferenceRequest(state=state, response_queue=response_queue, metadata={})
        self.request_queue.put(request)
        
        try:
            action = response_queue.get(timeout=timeout)
            return action
        except queue.Empty:
            # Fallback to random action on timeout
            action = random.choice(ACTIONS)
            log.warning(f"Inference timeout, returning random action: {action}")
            return action
    
    def _worker_loop(self) -> None:
        """Background worker for batched inference."""
        while True:
            try:
                # Collect batch of requests
                batch = self._collect_batch()
                if not batch:
                    continue
                
                # Process batch
                self._process_batch(batch)
                
            except Exception as e:
                log.error(f"Error in inference worker: {e}", exc_info=True)
                time.sleep(0.1)
    
    def _collect_batch(self) -> list[InferenceRequest]:
        """Collect a batch of requests with timeout."""
        batch = []
        deadline = time.time() + (self.config.max_wait_ms / 1000.0)
        
        while len(batch) < self.config.max_batch_size:
            timeout = max(0, deadline - time.time())
            if timeout <= 0:
                break
            
            try:
                request = self.request_queue.get(timeout=timeout)
                batch.append(request)
            except queue.Empty:
                break
        
        return batch
    
    def _process_batch(self, batch: list[InferenceRequest]) -> None:
        """Process a batch of inference requests."""
        # Stack states for batch prediction
        states = np.stack([req.state for req in batch])
        
        # Get Q-values from model
        with self.agent._model_lock:
            q_values = self.agent.model.predict(states, verbose=0)
        
        # Generate actions for each request
        for request, q_vals in zip(batch, q_values):
            # Epsilon-greedy action selection
            # Epsilon-greedy selection
            if random.random() < self.agent.epsilon:
                action = random.choice(ACTIONS)
            else:
                action = ACTIONS[int(np.argmax(q_vals))]

            # Resource-aware promotion (if caller provided metadata with ratios)
            try:
                cpu_ratio = float(request.metadata.get('cpu_ratio', 1.0)) if request.metadata else 1.0
                mem_ratio = float(request.metadata.get('mem_ratio', 1.0)) if request.metadata else 1.0
                headroom_ok = max(cpu_ratio, mem_ratio) < 0.6
                if action == 'wait' and headroom_ok:
                    action = 'deploy'
            except Exception:
                pass
            
            # Send response
            try:
                request.response_queue.put_nowait(action)
            except queue.Full:
                pass  # Client already timed out


def create_inference_service(agent: DQNAgent) -> InferenceService:
    """Create and return inference service."""
    return InferenceService(agent)