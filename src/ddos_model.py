#!/usr/bin/env python3
"""
PyTorch Model Classes for DDoS Detection
Extracted from LSTM_Ddos-2.ipynb
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset

class DDoSMultiTaskLSTM(nn.Module):
    """
    Multi-task LSTM model for DDoS detection - PyTorch Version
    - Classification: Binary attack/no-attack prediction  
    - Regression: Attack intensity/percentage prediction
    - DYNAMIC FEATURE SIZE: Automatically adapts to any number of input features
    """

    def __init__(self, input_size, hidden_size=64, num_layers=2, dropout=0.2):
        super(DDoSMultiTaskLSTM, self).__init__()

        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        print(f"Model initialized with {input_size} features (AUTO-DETECTED)")

        # Shared LSTM backbone
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )

        # Shared feature extraction
        self.shared_fc = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        # Classification head (binary attack/no-attack)
        self.classifier = nn.Sequential(
            nn.Linear(32, 16),
            nn.ReLU(), 
            nn.Dropout(dropout),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

        # Regression head (attack intensity 0-1)
        self.regressor = nn.Sequential(
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(16, 1),
            nn.Sigmoid()  # Ensures output between 0-1
        )

    def forward(self, x):
        """
        Forward pass
        Args:
            x: (batch_size, sequence_length, input_size)
        Returns:
            classification_output: (batch_size, 1) - probability of attack
            regression_output: (batch_size, 1) - attack intensity 0-1
        """
        batch_size = x.size(0)

        # Initialize hidden state
        h0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, batch_size, self.hidden_size).to(x.device)

        # LSTM forward pass
        lstm_out, (hn, cn) = self.lstm(x, (h0, c0))

        # Use the last time step output
        last_output = lstm_out[:, -1]  # (batch_size, hidden_size)

        # Shared feature extraction
        shared_features = self.shared_fc(last_output)

        # Task-specific heads
        classification_output = self.classifier(shared_features)
        regression_output = self.regressor(shared_features)

        return classification_output, regression_output


class MultiTaskLoss(nn.Module):
    """Combined loss for multi-task learning"""

    def __init__(self, alpha=1.0, beta=0.3):
        super(MultiTaskLoss, self).__init__()
        self.alpha = alpha  # Weight for classification loss
        self.beta = beta    # Weight for regression loss

        self.bce_loss = nn.BCELoss()
        self.mse_loss = nn.MSELoss()

    def forward(self, class_pred, class_target, reg_pred, reg_target):
        """Combined loss calculation"""

        # Classification loss
        classification_loss = self.bce_loss(class_pred, class_target)

        # Regression loss  
        regression_loss = self.mse_loss(reg_pred, reg_target)

        # Combined loss
        total_loss = self.alpha * classification_loss + self.beta * regression_loss

        return total_loss, classification_loss, regression_loss


class DDoSSequenceDataset(Dataset):
    """Dataset class for DDoS detection sequences with OVERLAPPING support"""

    def __init__(self, sequences, classification_labels, regression_labels):
        self.sequences = torch.FloatTensor(sequences)
        self.classification_labels = torch.FloatTensor(classification_labels).unsqueeze(1)
        self.regression_labels = torch.FloatTensor(regression_labels).unsqueeze(1)

        print(f"Dataset created:")
        print(f"  - Sequences shape: {self.sequences.shape}")
        print(f"  - Features per window: {self.sequences.shape[2]}")
        print(f"  - Sequence length: {self.sequences.shape[1]}")
        print(f"  - Total sequences: {len(self.sequences)}")

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return (
            self.sequences[idx], 
            self.classification_labels[idx],
            self.regression_labels[idx]
        )


def create_model(input_size: int, hidden_size: int = 64, num_layers: int = 2, dropout: float = 0.2):
    """Factory function to create DDoS detection model"""
    return DDoSMultiTaskLSTM(
        input_size=input_size,
        hidden_size=hidden_size,
        num_layers=num_layers,
        dropout=dropout
    )


def create_loss_function(alpha: float = 1.0, beta: float = 0.3):
    """Factory function to create multi-task loss"""
    return MultiTaskLoss(alpha=alpha, beta=beta)


if __name__ == "__main__":
    print("Testing DDoS Model Architecture")

    # Test model creation
    input_size = 47  # From notebook feature engineering
    model = create_model(input_size)

    # Test forward pass
    batch_size = 2
    sequence_length = 50

    # Create sample input
    x = torch.randn(batch_size, sequence_length, input_size)

    # Forward pass
    class_output, reg_output = model(x)

    print(f"\nModel test:")
    print(f"Input shape: {x.shape}")
    print(f"Classification output shape: {class_output.shape}")
    print(f"Regression output shape: {reg_output.shape}")
    print(f"Classification output range: {class_output.min().item():.3f} - {class_output.max().item():.3f}")
    print(f"Regression output range: {reg_output.min().item():.3f} - {reg_output.max().item():.3f}")

    # Test loss function
    loss_fn = create_loss_function()

    # Create sample targets
    class_target = torch.randint(0, 2, (batch_size, 1)).float()
    reg_target = torch.rand(batch_size, 1)

    # Calculate loss
    total_loss, class_loss, reg_loss = loss_fn(class_output, class_target, reg_output, reg_target)

    print(f"\nLoss test:")
    print(f"Total loss: {total_loss.item():.4f}")
    print(f"Classification loss: {class_loss.item():.4f}")
    print(f"Regression loss: {reg_loss.item():.4f}")

    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    print(f"\nModel parameters:")
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
