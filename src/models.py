"""
Injection Detection Models
Contains the neural network architectures for injection detection
Based on GBST tokenization and Transformer encoding
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional
import warnings
from charformer_pytorch import GBST
warnings.filterwarnings('ignore')

class InjectionDetectionModel(nn.Module):
    """
    Enhanced model with better regularization
    Uses GBST tokenization + Transformer encoder + MLP classification head
    """
    def __init__(self,
                 num_tokens: int = 257,
                 dim: int = 128,
                 max_block_size: int = 4,
                 score_consensus_attn: bool = True,
                 d_model: int = 128,
                 nhead: int = 1,
                 dim_feedforward: int = 256,
                 num_layers: int = 1,
                 max_length: int = 2048,
                 downsample_factor: int = 4,
                 mlp_hidden_dims: List[int] = [256, 128],
                 dropout: float = 0.2,
                 attack_type: str = "unknown"):

        super(InjectionDetectionModel, self).__init__()

        self.attack_type = attack_type
        self.max_length = max_length
        self.downsample_factor = downsample_factor
        self.d_model = d_model
        self.gbst_norm = nn.LayerNorm(d_model)

        # GBST architecture for efficient tokenization
        self.gbst = GBST(
            num_tokens=num_tokens,
            dim=dim,
            max_block_size=max_block_size,
            score_consensus_attn=score_consensus_attn
        )

        # Transformer encoder with increased dropout for regularization
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Enhanced MLP with Batch Normalization and dropout
        mlp_layers = []
        input_dim = d_model

        for hidden_dim in mlp_hidden_dims:
            mlp_layers.extend([
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.BatchNorm1d(hidden_dim),  # Added batch normalization
                nn.Dropout(dropout)
            ])
            input_dim = hidden_dim

        mlp_layers.append(nn.Linear(input_dim, 1))
        self.mlp = nn.Sequential(*mlp_layers)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """Forward pass through GBST -> Transformer -> Classification head"""
        batch_size = x.size(0)

        # GBST Tokenization
        gbst_output = self.gbst(x)
        if isinstance(gbst_output, tuple):
            gbst_output, gbst_mask = gbst_output

        gbst_output = self.gbst_norm(gbst_output)

        # Transformer Encoder
        if attention_mask is not None:
            attention_mask = attention_mask[:, ::self.downsample_factor]

        encoder_output = self.transformer_encoder(
            gbst_output,
            src_key_padding_mask=attention_mask if attention_mask is not None else None
        )

        # Classification with attention masking
        if attention_mask is not None:
            mask_expanded = (~attention_mask).unsqueeze(-1).expand_as(encoder_output)
            encoder_output = encoder_output * mask_expanded.float()
            pooled = encoder_output.sum(dim=1) / mask_expanded.sum(dim=1)
        else:
            pooled = encoder_output.mean(dim=1)

        logits = self.mlp(pooled)
        probabilities = self.sigmoid(logits)

        return {
            'logits': logits.squeeze(-1),
            'probabilities': probabilities.squeeze(-1),
            'encoder_output': encoder_output,
            'attention_weights': None
        }


class MultiClassInjectionModel(nn.Module):
    """
    Transfer learning model for multi-class attack classification
    Replaces binary classification head with multi-class head
    Supports: SQLi, Command Injection, XSS, Path Traversal
    """

    def __init__(self, base_model: nn.Module, num_classes: int = 4, hidden_dim: int = 128):
        super(MultiClassInjectionModel, self).__init__()

        # Keep original model components (transfer learning)
        self.gbst = base_model.gbst
        self.gbst_norm = base_model.gbst_norm
        self.transformer_encoder = base_model.transformer_encoder
        self.d_model = base_model.d_model
        self.downsample_factor = base_model.downsample_factor

        # Replace binary classification head with multi-class head
        self.multi_class_head = nn.Sequential(
            nn.Linear(self.d_model, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, num_classes)
        )

        print(f"Multi-class model created with {num_classes} classes")

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """Forward pass for multi-class classification"""
        batch_size = x.size(0)

        # GBST encoding (reuse from base model)
        gbst_output = self.gbst(x)
        if isinstance(gbst_output, tuple):
            gbst_output, _ = gbst_output
        gbst_output = self.gbst_norm(gbst_output)

        # Transformer encoding (reuse from base model)
        if attention_mask is not None:
            attention_mask = attention_mask[:, ::self.downsample_factor]

        encoder_output = self.transformer_encoder(
            gbst_output,
            src_key_padding_mask=attention_mask if attention_mask is not None else None
        )

        # Pooling
        if attention_mask is not None:
            mask_expanded = (~attention_mask).unsqueeze(-1).expand_as(encoder_output)
            encoder_output = encoder_output * mask_expanded.float()
            pooled = encoder_output.sum(dim=1) / mask_expanded.sum(dim=1)
        else:
            pooled = encoder_output.mean(dim=1)

        # Multi-class classification
        logits = self.multi_class_head(pooled)
        probabilities = torch.softmax(logits, dim=-1)

        return {
            'logits': logits,
            'probabilities': probabilities,
            'encoder_output': encoder_output
        }


# Model configuration constants
DEFAULT_MODEL_CONFIG = {
    'num_tokens': 257,
    'dim': 128,
    'max_block_size': 4,
    'score_consensus_attn': True,
    'd_model': 128,
    'nhead': 1,
    'dim_feedforward': 256,
    'num_layers': 1,
    'max_length': 2048,
    'downsample_factor': 4,
    'mlp_hidden_dims': [256, 128],
    'dropout': 0.2
}

# Attack type mappings
ATTACK_TYPES = ['sqli', 'commandi', 'xss', 'traversal']

# Utility functions
def create_binary_model(config: Dict = None) -> InjectionDetectionModel:
    """Create a binary injection detection model with default or custom config"""
    if config is None:
        config = DEFAULT_MODEL_CONFIG
    return InjectionDetectionModel(**config)

def create_multiclass_model(base_model: InjectionDetectionModel, 
                           num_classes: int = 4, 
                           hidden_dim: int = 128) -> MultiClassInjectionModel:
    """Create a multi-class model from a binary base model"""
    return MultiClassInjectionModel(base_model, num_classes, hidden_dim)

def load_pretrained_models(binary_path: str, multiclass_path: str, device: str = 'cpu'):
    """
    Load both binary and multi-class pretrained models

    Args:
        binary_path: Path to binary model checkpoint
        multiclass_path: Path to multi-class model checkpoint  
        device: Device to load models on ('cpu' or 'cuda')

    Returns:
        Tuple of (binary_model, multiclass_model)
    """
    # Load binary model
    binary_model = create_binary_model()
    binary_model.load_state_dict(torch.load(binary_path, map_location=device))
    binary_model.to(device)
    binary_model.eval()

    # Load multi-class model
    base_model = create_binary_model()
    multiclass_model = create_multiclass_model(base_model)
    multiclass_model.load_state_dict(torch.load(multiclass_path, map_location=device))
    multiclass_model.to(device)
    multiclass_model.eval()

    return binary_model, multiclass_model
