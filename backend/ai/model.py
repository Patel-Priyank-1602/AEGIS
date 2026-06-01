"""
AEGIS LSTM Autoencoder
Neural network that learns normal system behavior patterns.
When new events deviate from learned patterns, reconstruction error increases,
indicating anomalous behavior.
"""

import torch
import torch.nn as nn


class LSTMAutoencoder(nn.Module):
    """
    LSTM Autoencoder for behavioral anomaly detection.
    
    Architecture:
        Encoder: Multi-layer LSTM that compresses event sequences into latent space
        Decoder: Multi-layer LSTM that reconstructs the original sequences
    
    The reconstruction error (MSE between input and output) serves as the
    anomaly score. High error = the model has never seen behavior like this
    during training = likely anomalous.
    """

    def __init__(self, input_size: int = 10, hidden_size: int = 64, num_layers: int = 2):
        super(LSTMAutoencoder, self).__init__()

        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        # ENCODER: compress the behavior sequence into a latent representation
        self.encoder = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2
        )

        # Bottleneck: further compress the encoded representation
        self.bottleneck = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, hidden_size),
            nn.ReLU()
        )

        # DECODER: reconstruct the behavior sequence from latent space
        self.decoder = nn.LSTM(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2
        )

        # Output projection back to input dimensions
        self.output_layer = nn.Linear(hidden_size, input_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through the autoencoder.
        
        Args:
            x: Input tensor of shape (batch_size, sequence_length, input_size)
        
        Returns:
            Reconstructed tensor of same shape as input
        """
        batch_size = x.size(0)
        seq_len = x.size(1)

        # Encode: compress sequence to hidden representation
        encoded, (hidden, cell) = self.encoder(x)

        # Bottleneck: squeeze the last hidden state
        latent = self.bottleneck(hidden[-1])  # (batch_size, hidden_size)

        # Repeat latent for each timestep in the sequence
        decoder_input = latent.unsqueeze(1).repeat(1, seq_len, 1)

        # Decode: reconstruct the original sequence
        decoded, _ = self.decoder(decoder_input)

        # Project back to input dimensions
        output = self.output_layer(decoded)

        return output

    def anomaly_score(self, x: torch.Tensor, baseline_mse: float = 0.015) -> float:
        """
        Compute anomaly score for the most recent event in the sequence.
        
        Uses adaptive scaling based on the model's baseline reconstruction error
        from training. This ensures:
          - Normal events (MSE near baseline) score 0-25 (safe)
          - Slightly unusual events score 30-65 (warning)
          - Truly anomalous events (MSE >> baseline) score 70-100 (danger)
        
        Args:
            x: Input tensor (batch_size, seq_len, features)
            baseline_mse: The model's average training loss, used as the "normal" threshold
        """
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            
            # Evaluate reconstruction error of the LATEST event only
            latest_event = x[:, -1, :]
            latest_recon = reconstructed[:, -1, :]
            mse = torch.mean((latest_event - latest_recon) ** 2).item()
            
            # Adaptive scaling: how many times worse than baseline is this event?
            # ratio = 1.0 means perfectly normal, ratio = 5.0 means 5x worse than training
            ratio = mse / max(baseline_mse, 1e-6)
            
            # Map ratio to 0-100 score with tighter thresholds:
            #   ratio < 1.2  →  score 0-10   (safe: well within normal variance)
            #   ratio 1.2-2  →  score 10-30  (safe but elevated)
            #   ratio 2-4    →  score 30-65  (warning: noticeably different from training)
            #   ratio 4-6    →  score 65-85  (danger: very anomalous)
            #   ratio > 6    →  score 85-100 (critical: completely foreign to model)
            if ratio < 1.2:
                score = ratio * 8.0  # Normal: 0-10
            elif ratio < 2.0:
                score = 10.0 + (ratio - 1.2) * 25.0  # Elevated: 10-30
            elif ratio < 4.0:
                score = 30.0 + (ratio - 2.0) * 17.5  # Warning: 30-65
            elif ratio < 6.0:
                score = 65.0 + (ratio - 4.0) * 10.0  # Danger: 65-85
            else:
                score = 85.0 + min((ratio - 6.0) * 3.0, 15.0)  # Critical: 85-100
            
            return round(min(score, 100.0), 2)

    def get_per_event_scores(self, x: torch.Tensor) -> list:
        """
        Get individual anomaly scores for each event in the sequence.
        Useful for pinpointing which exact event is suspicious.
        """
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            per_event_mse = torch.mean((x - reconstructed) ** 2, dim=-1)
            scores = (per_event_mse * 1000).clamp(0, 100)
            return scores.squeeze().tolist()
