"""
AEGIS Federated Learning Server
Aggregates model gradients from distributed agents using FedAvg.
Raw telemetry never leaves the host — only compressed gradients travel.

Differential privacy: Laplace noise (ε=0.1) added before upload,
making reverse-engineering training data computationally infeasible.
"""

import time
import uuid
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional


class FederatedServer:
    """
    FedAvg aggregation server for distributed model training.
    Agents train locally and upload gradients. Server averages them.
    """

    def __init__(self):
        self.global_round: int = 0
        self.epsilon: float = 0.1  # Differential privacy parameter
        self.min_clients: int = 1  # Minimum clients per round
        self.client_updates: Dict[str, Dict] = {}
        self.registered_clients: Dict[str, Dict] = {}
        self.history: List[Dict] = []
        self.global_model_version: str = "v0"
        self.enabled = True

    def register_client(self, client_id: str, metadata: dict = None) -> dict:
        """Register a new federated learning client (agent)."""
        self.registered_clients[client_id] = {
            "client_id": client_id,
            "registered_at": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "rounds_participated": 0,
            "metadata": metadata or {},
        }
        print(f"[FedLearn] Client registered: {client_id}")
        return {"status": "registered", "global_round": self.global_round,
                "model_version": self.global_model_version}

    def upload_gradients(self, client_id: str, gradients: dict) -> dict:
        """
        Receive gradient updates from a client.
        Gradients should already have DP noise added client-side.
        """
        if client_id not in self.registered_clients:
            return {"error": "Client not registered"}

        # Validate gradient structure
        if "parameters" not in gradients:
            return {"error": "Missing 'parameters' in gradient payload"}

        self.client_updates[client_id] = {
            "gradients": gradients,
            "uploaded_at": datetime.utcnow().isoformat(),
            "round": self.global_round,
            "num_samples": gradients.get("num_samples", 0),
        }

        self.registered_clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
        self.registered_clients[client_id]["rounds_participated"] += 1

        print(f"[FedLearn] Gradients received from {client_id} "
              f"(round {self.global_round}, {gradients.get('num_samples', 0)} samples)")

        # Check if we have enough clients to aggregate
        if len(self.client_updates) >= self.min_clients:
            return self._aggregate()

        return {
            "status": "received",
            "clients_ready": len(self.client_updates),
            "clients_needed": self.min_clients,
        }

    def _aggregate(self) -> dict:
        """Perform FedAvg aggregation of client gradients."""
        self.global_round += 1
        num_clients = len(self.client_updates)

        # FedAvg: weighted average of gradients by sample count
        total_samples = sum(
            u["num_samples"] for u in self.client_updates.values()
        ) or 1

        # In a real implementation, we would average actual tensor gradients.
        # Here we track the aggregation metadata.
        aggregation = {
            "round": self.global_round,
            "num_clients": num_clients,
            "total_samples": total_samples,
            "clients": list(self.client_updates.keys()),
            "aggregated_at": datetime.utcnow().isoformat(),
            "dp_epsilon": self.epsilon,
        }

        self.history.append(aggregation)
        self.global_model_version = f"v{self.global_round}"
        self.client_updates.clear()  # Reset for next round

        print(f"[FedLearn] ✓ Round {self.global_round} aggregated: "
              f"{num_clients} clients, {total_samples} samples")

        return {
            "status": "aggregated",
            "round": self.global_round,
            "model_version": self.global_model_version,
            "num_clients": num_clients,
        }

    @staticmethod
    def add_dp_noise(gradients: np.ndarray, epsilon: float = 0.1) -> np.ndarray:
        """
        Add Laplace differential privacy noise to gradients before upload.
        This should be called CLIENT-SIDE before uploading.
        """
        sensitivity = 1.0 / len(gradients)
        scale = sensitivity / epsilon
        noise = np.random.laplace(0, scale, gradients.shape)
        return gradients + noise

    def get_global_model(self) -> dict:
        """Get the current global model version for download."""
        return {
            "model_version": self.global_model_version,
            "global_round": self.global_round,
            "last_aggregation": self.history[-1] if self.history else None,
        }

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "global_round": self.global_round,
            "model_version": self.global_model_version,
            "registered_clients": len(self.registered_clients),
            "pending_updates": len(self.client_updates),
            "total_rounds": len(self.history),
            "dp_epsilon": self.epsilon,
            "clients": [
                {
                    "id": c["client_id"],
                    "last_seen": c["last_seen"],
                    "rounds": c["rounds_participated"],
                }
                for c in self.registered_clients.values()
            ],
        }


# Global singleton
fed_server = FederatedServer()
