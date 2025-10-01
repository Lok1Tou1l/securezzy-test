#!/usr/bin/env python3
"""
LSTM-based DDoS Detection Service
Extracted from LSTM_Ddos-2.ipynb with production enhancements
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import time
import threading
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import deque, defaultdict
import warnings
warnings.filterwarnings('ignore')

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


class TimeBasedDDoSPreprocessor:
    """
    Time-based DDoS preprocessing pipeline from the notebook
    Creates fixed 2-second time windows with comprehensive feature engineering
    """

    def __init__(self):
        self.scaler = None
        self.feature_names = [
            'flow_rate', 'packet_rate', 'fwd_packet_rate', 'bwd_packet_rate',
            'total_flows', 'total_packets', 'total_fwd_packets', 'total_bwd_packets',
            'avg_packets_per_flow', 'max_packets_per_flow', 'min_packets_per_flow',
            'unique_src_ips', 'unique_dst_ips', 'unique_src_ports', 'unique_dst_ports',
            'src_ip_diversity_ratio', 'dst_ip_concentration_ratio',
            'rdp_targeting_ratio', 'smb_targeting_ratio', 'http_targeting_ratio',
            'https_targeting_ratio', 'well_known_ports_ratio', 'most_targeted_port_ratio',
            'fwd_bwd_packet_ratio', 'fwd_packet_percentage', 'zero_bwd_flows_ratio',
            'zero_fwd_flows_ratio', 'unidirectional_flows_ratio',
            'window_duration', 'avg_flow_duration', 'max_flow_duration', 'duration_std',
            'short_flows_ratio', 'zero_duration_ratio',
            'packet_count_variance', 'packet_count_skewness', 'duration_variance',
            'fwd_packet_variance', 'bwd_packet_variance',
            'high_volume_flows_ratio', 'burst_flows_ratio', 'potential_flooding_indicator',
            'flow_density', 'connection_intensity',
            'src_port_entropy', 'dst_port_entropy', 'packet_size_entropy'
        ]

    def engineer_time_window_features(self, window_data: pd.DataFrame, window_duration: float = 2.0) -> Dict[str, float]:
        """
        Comprehensive feature engineering for time-based windows
        Extracted from the notebook's feature engineering pipeline
        """
        total_flows = len(window_data)

        if total_flows == 0:
            return self.get_empty_features()

        # Basic aggregations
        total_packets = window_data['packets_count'].sum() if 'packets_count' in window_data.columns else 0
        total_fwd_packets = window_data['fwd_packets_count'].sum() if 'fwd_packets_count' in window_data.columns else 0
        total_bwd_packets = window_data['bwd_packets_count'].sum() if 'bwd_packets_count' in window_data.columns else 0

        features = {
            # RATE FEATURES - Now truly meaningful with fixed time
            'flow_rate': total_flows / window_duration,  # Flows per second
            'packet_rate': total_packets / window_duration,  # Packets per second
            'fwd_packet_rate': total_fwd_packets / window_duration,
            'bwd_packet_rate': total_bwd_packets / window_duration,

            # VOLUME FEATURES
            'total_flows': total_flows,
            'total_packets': total_packets,
            'total_fwd_packets': total_fwd_packets,
            'total_bwd_packets': total_bwd_packets,
            'avg_packets_per_flow': window_data['packets_count'].mean() if 'packets_count' in window_data.columns else 0,
            'max_packets_per_flow': window_data['packets_count'].max() if 'packets_count' in window_data.columns else 0,
            'min_packets_per_flow': window_data['packets_count'].min() if 'packets_count' in window_data.columns else 0,

            # CONNECTION DIVERSITY
            'unique_src_ips': window_data['src_ip'].nunique() if 'src_ip' in window_data.columns else 0,
            'unique_dst_ips': window_data['dst_ip'].nunique() if 'dst_ip' in window_data.columns else 0,
            'unique_src_ports': window_data['src_port'].nunique() if 'src_port' in window_data.columns else 0,
            'unique_dst_ports': window_data['dst_port'].nunique() if 'dst_port' in window_data.columns else 0,
            'src_ip_diversity_ratio': window_data['src_ip'].nunique() / total_flows if 'src_ip' in window_data.columns else 0,
            'dst_ip_concentration_ratio': total_flows / max(window_data['dst_ip'].nunique(), 1) if 'dst_ip' in window_data.columns else 0,

            # PORT TARGETING PATTERNS
            'rdp_targeting_ratio': (window_data['dst_port'] == 3389).sum() / total_flows if 'dst_port' in window_data.columns else 0,
            'smb_targeting_ratio': (window_data['dst_port'] == 445).sum() / total_flows if 'dst_port' in window_data.columns else 0,
            'http_targeting_ratio': (window_data['dst_port'] == 80).sum() / total_flows if 'dst_port' in window_data.columns else 0,
            'https_targeting_ratio': (window_data['dst_port'] == 443).sum() / total_flows if 'dst_port' in window_data.columns else 0,
            'well_known_ports_ratio': (window_data['dst_port'] <= 1023).sum() / total_flows if 'dst_port' in window_data.columns else 0,
            'most_targeted_port_ratio': window_data['dst_port'].value_counts().iloc[0] / total_flows if 'dst_port' in window_data.columns and not window_data.empty else 0,

            # DIRECTIONAL FLOW PATTERNS
            'fwd_bwd_packet_ratio': total_fwd_packets / max(total_bwd_packets, 1),
            'fwd_packet_percentage': total_fwd_packets / max(total_packets, 1),
            'zero_bwd_flows_ratio': (window_data['bwd_packets_count'] == 0).sum() / total_flows if 'bwd_packets_count' in window_data.columns else 0,
            'zero_fwd_flows_ratio': (window_data['fwd_packets_count'] == 0).sum() / total_flows if 'fwd_packets_count' in window_data.columns else 0,
            'unidirectional_flows_ratio': ((window_data['bwd_packets_count'] == 0) | (window_data['fwd_packets_count'] == 0)).sum() / total_flows if all(col in window_data.columns for col in ['bwd_packets_count', 'fwd_packets_count']) else 0,

            # TEMPORAL CHARACTERISTICS - Now more meaningful
            'window_duration': window_duration,  # Always exactly 2.0
            'avg_flow_duration': window_data['duration'].mean() if 'duration' in window_data.columns else 0,
            'max_flow_duration': window_data['duration'].max() if 'duration' in window_data.columns else 0,
            'duration_std': window_data['duration'].std() if 'duration' in window_data.columns else 0,
            'short_flows_ratio': (window_data['duration'] < 1.0).sum() / total_flows if 'duration' in window_data.columns else 0,
            'zero_duration_ratio': (window_data['duration'] == 0).sum() / total_flows if 'duration' in window_data.columns else 0,

            # STATISTICAL FEATURES
            'packet_count_variance': window_data['packets_count'].var() if 'packets_count' in window_data.columns else 0,
            'packet_count_skewness': window_data['packets_count'].skew() if 'packets_count' in window_data.columns else 0,
            'duration_variance': window_data['duration'].var() if 'duration' in window_data.columns else 0,
            'fwd_packet_variance': window_data['fwd_packets_count'].var() if 'fwd_packets_count' in window_data.columns else 0,
            'bwd_packet_variance': window_data['bwd_packets_count'].var() if 'bwd_packets_count' in window_data.columns else 0,

            # ATTACK INDICATORS
            'high_volume_flows_ratio': (window_data['packets_count'] > 1000).sum() / total_flows if 'packets_count' in window_data.columns else 0,
            'burst_flows_ratio': (window_data['packets_count'] > window_data['packets_count'].quantile(0.95)).sum() / total_flows if 'packets_count' in window_data.columns else 0,
            'potential_flooding_indicator': (window_data['packets_count'] > 5).sum() / total_flows if 'packets_count' in window_data.columns else 0,

            # DENSITY FEATURES - New - meaningful with fixed time
            'flow_density': total_flows,  # Number of flows in this 2-second window
            'connection_intensity': window_data['src_ip'].nunique() * window_data['dst_ip'].nunique() if all(col in window_data.columns for col in ['src_ip', 'dst_ip']) else 0,

            # ENTROPY MEASURES
            'src_port_entropy': self.calculate_entropy(window_data['src_port']) if 'src_port' in window_data.columns else 0,
            'dst_port_entropy': self.calculate_entropy(window_data['dst_port']) if 'dst_port' in window_data.columns else 0,
            'packet_size_entropy': self.calculate_entropy(window_data['packets_count']) if 'packets_count' in window_data.columns else 0
        }

        return features

    def calculate_entropy(self, series: pd.Series) -> float:
        """Calculate Shannon entropy for a series"""
        if len(series) == 0:
            return 0.0

        value_counts = series.value_counts()
        probabilities = value_counts / len(series)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return float(entropy)

    def get_empty_features(self) -> Dict[str, float]:
        """Return zero-filled features for empty windows"""
        return {name: 0.0 for name in self.feature_names}

    def create_time_windows(self, data: pd.DataFrame, window_duration: float = 2.0, 
                           step_duration: float = 1.0) -> List[Dict[str, float]]:
        """
        Create time-based windows with feature engineering
        """
        if 'timestamp' not in data.columns:
            raise ValueError("Data must contain 'timestamp' column")

        # Convert timestamp and sort
        data['timestamp'] = pd.to_datetime(data['timestamp'])
        data = data.sort_values('timestamp').reset_index(drop=True)

        windows = []

        # Time range
        start_time = data['timestamp'].min()
        end_time = data['timestamp'].max()

        window_duration_td = pd.Timedelta(seconds=window_duration)
        step_duration_td = pd.Timedelta(seconds=step_duration)

        current_start = start_time

        while current_start + window_duration_td <= end_time:
            current_end = current_start + window_duration_td

            # Extract flows within this time window
            mask = (data['timestamp'] >= current_start) & (data['timestamp'] < current_end)
            window_data = data[mask].copy()

            if len(window_data) > 0:  # Only process non-empty windows
                # Engineer features for this time window
                features = self.engineer_time_window_features(window_data, window_duration)
                windows.append(features)

            current_start += step_duration_td

        return windows

    def fit_scaler(self, windows: List[Dict[str, float]]):
        """Fit the scaler on feature windows"""
        if not windows:
            raise ValueError("No windows to fit scaler on")

        # Convert to DataFrame
        df = pd.DataFrame(windows)

        # Handle missing values
        df = df.fillna(0)

        # Handle infinite values
        df = df.replace([np.inf, -np.inf], 0)

        # Fit scaler
        self.scaler = StandardScaler()
        self.scaler.fit(df)

        print(f"Scaler fitted on {len(windows)} windows with {len(self.feature_names)} features")

    def transform_windows(self, windows: List[Dict[str, float]]) -> np.ndarray:
        """Transform feature windows using fitted scaler"""
        if self.scaler is None:
            raise ValueError("Scaler not fitted. Call fit_scaler() first.")

        if not windows:
            return np.array([])

        # Convert to DataFrame
        df = pd.DataFrame(windows)

        # Handle missing values and infinite values
        df = df.fillna(0)
        df = df.replace([np.inf, -np.inf], 0)

        # Ensure all feature columns are present
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0.0

        # Select and order features
        df = df[self.feature_names]

        # Transform
        normalized = self.scaler.transform(df)

        return normalized


class LSTMDDoSDetectionService:
    """
    Production LSTM-based DDoS Detection Service
    Integrates time-based preprocessing with LSTM model
    """

    def __init__(self, 
                 model_path: str = None,
                 sequence_length: int = 50,
                 window_duration: float = 2.0,
                 step_duration: float = 1.0,
                 device: str = None):

        self.sequence_length = sequence_length
        self.window_duration = window_duration
        self.step_duration = step_duration
        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')

        # Initialize preprocessor
        self.preprocessor = TimeBasedDDoSPreprocessor()

        # Model and scaler will be loaded
        self.model = None
        self.model_loaded = False

        # Statistics
        self.detection_count = 0
        self.attack_detections = 0
        self.processing_times = deque(maxlen=100)

        # Thread safety
        self.lock = threading.RLock()

        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('LSTMDDoSService')

        if model_path:
            self.load_model(model_path)

        self.logger.info(f"🚀 LSTM DDoS Detection Service initialized on {self.device}")
        self.logger.info(f"   Sequence length: {sequence_length} windows")
        self.logger.info(f"   Window duration: {window_duration} seconds")
        self.logger.info(f"   Step duration: {step_duration} seconds")

    def load_model(self, model_path: str):
        """Load trained model and scaler"""
        try:
            checkpoint = torch.load(model_path, map_location=self.device)

            # Extract model configuration
            model_config = checkpoint.get('model_config', {})
            input_size = model_config.get('input_size', 47)  # Default from notebook

            # Initialize model
            self.model = DDoSMultiTaskLSTM(
                input_size=input_size,
                hidden_size=model_config.get('hidden_size', 64),
                num_layers=model_config.get('num_layers', 2),
                dropout=model_config.get('dropout', 0.2)
            )

            # Load model weights
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()

            # Load scaler if available
            if 'scaler_params' in checkpoint:
                scaler_params = checkpoint['scaler_params']
                self.preprocessor.scaler = StandardScaler()
                self.preprocessor.scaler.mean_ = scaler_params['mean_']
                self.preprocessor.scaler.scale_ = scaler_params['scale_']
                self.preprocessor.scaler.var_ = scaler_params['var_']
                self.preprocessor.scaler.n_features_in_ = scaler_params['n_features_in_']

            self.model_loaded = True
            self.logger.info(f"✅ Model loaded from {model_path}")

        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            self.model_loaded = False

    def create_sequences(self, windows: np.ndarray) -> np.ndarray:
        """
        Create overlapping sequences from windows
        Based on the notebook's overlapping sequence creation
        """
        if len(windows) < self.sequence_length:
            return np.array([])

        sequences = []

        # OVERLAPPING sliding window approach
        for i in range(len(windows) - self.sequence_length + 1):
            sequence = windows[i:i + self.sequence_length]
            sequences.append(sequence)

        return np.array(sequences)

    def predict_sequence(self, sequence: np.ndarray) -> Dict[str, Any]:
        """Make real-time prediction on a sequence"""
        if not self.model_loaded:
            return {
                'attack_detected': False,
                'attack_probability': 0.0,
                'attack_intensity': 0.0,
                'confidence': 0.0,
                'error': 'Model not loaded'
            }

        try:
            with torch.no_grad():
                # Convert to tensor and add batch dimension
                sequence_tensor = torch.FloatTensor(sequence).unsqueeze(0).to(self.device)

                # Model prediction
                class_pred, reg_pred = self.model(sequence_tensor)

                attack_probability = float(class_pred.item())
                attack_intensity = float(reg_pred.item())
                attack_detected = bool(attack_probability > 0.5)
                confidence = float(abs(attack_probability - 0.5) * 2)

                return {
                    'attack_detected': attack_detected,
                    'attack_probability': attack_probability,
                    'attack_intensity': attack_intensity,
                    'confidence': confidence
                }

        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return {
                'attack_detected': False,
                'attack_probability': 0.0,
                'attack_intensity': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }

    def analyze_traffic_data(self, traffic_data: pd.DataFrame, 
                            detection_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze traffic data for DDoS attacks
        Main detection interface
        """
        start_time = time.time()

        with self.lock:
            self.detection_count += 1

        try:
            # Step 1: Create time windows with feature engineering
            windows = self.preprocessor.create_time_windows(
                traffic_data, 
                self.window_duration, 
                self.step_duration
            )

            if not windows:
                return {
                    'attack_detected': False,
                    'windows_created': 0,
                    'sequences_created': 0,
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'error': 'No time windows created from data'
                }

            # Step 2: Normalize features
            if self.preprocessor.scaler is None:
                # If no pre-trained scaler, fit on current data (not recommended for production)
                self.preprocessor.fit_scaler(windows)
                self.logger.warning("No pre-trained scaler found, fitting on current data")

            normalized_windows = self.preprocessor.transform_windows(windows)

            # Step 3: Create sequences
            sequences = self.create_sequences(normalized_windows)

            if len(sequences) == 0:
                return {
                    'attack_detected': False,
                    'windows_created': len(windows),
                    'sequences_created': 0,
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'error': f'Insufficient windows for sequence creation (need {self.sequence_length}, got {len(windows)})'
                }

            # Step 4: Predict on sequences
            predictions = []
            attack_probabilities = []
            attack_intensities = []

            for sequence in sequences:
                pred = self.predict_sequence(sequence)
                predictions.append(pred)
                attack_probabilities.append(pred['attack_probability'])
                attack_intensities.append(pred['attack_intensity'])

            # Step 5: Aggregate results
            max_attack_probability = max(attack_probabilities)
            avg_attack_probability = np.mean(attack_probabilities)
            max_attack_intensity = max(attack_intensities)
            avg_attack_intensity = np.mean(attack_intensities)

            # Determine overall attack status
            attack_detected = max_attack_probability > detection_threshold

            if attack_detected:
                with self.lock:
                    self.attack_detections += 1

            processing_time = (time.time() - start_time) * 1000

            with self.lock:
                self.processing_times.append(processing_time)

            return {
                'attack_detected': attack_detected,
                'max_attack_probability': max_attack_probability,
                'avg_attack_probability': avg_attack_probability,
                'max_attack_intensity': max_attack_intensity,
                'avg_attack_intensity': avg_attack_intensity,
                'confidence': abs(max_attack_probability - 0.5) * 2,
                'windows_created': len(windows),
                'sequences_created': len(sequences),
                'sequence_predictions': len(predictions),
                'processing_time_ms': processing_time,
                'threshold_used': detection_threshold,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Analysis error: {e}")
            return {
                'attack_detected': False,
                'error': str(e),
                'processing_time_ms': (time.time() - start_time) * 1000,
                'timestamp': datetime.utcnow().isoformat()
            }

    def analyze_live_traffic(self, flows: List[Dict[str, Any]], 
                            detection_threshold: float = 0.5) -> Dict[str, Any]:
        """
        Analyze live traffic flows (list of flow dictionaries)
        Converts to DataFrame format expected by the pipeline
        """
        try:
            # Convert flows to DataFrame
            df = pd.DataFrame(flows)

            # Ensure required columns exist with defaults
            required_columns = {
                'timestamp': datetime.utcnow(),
                'src_ip': '0.0.0.0',
                'dst_ip': '0.0.0.0',
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'TCP',
                'packets_count': 1,
                'fwd_packets_count': 0,
                'bwd_packets_count': 0,
                'duration': 0.0
            }

            for col, default_val in required_columns.items():
                if col not in df.columns:
                    df[col] = default_val

            return self.analyze_traffic_data(df, detection_threshold)

        except Exception as e:
            self.logger.error(f"Live traffic analysis error: {e}")
            return {
                'attack_detected': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        with self.lock:
            avg_processing_time = np.mean(self.processing_times) if self.processing_times else 0

            return {
                'model_loaded': self.model_loaded,
                'device': self.device,
                'sequence_length': self.sequence_length,
                'window_duration': self.window_duration,
                'step_duration': self.step_duration,
                'total_detections': self.detection_count,
                'attack_detections': self.attack_detections,
                'attack_detection_rate': self.attack_detections / max(self.detection_count, 1),
                'avg_processing_time_ms': avg_processing_time,
                'feature_count': len(self.preprocessor.feature_names),
                'scaler_fitted': self.preprocessor.scaler is not None
            }


# Global service instance
lstm_ddos_service = None

def get_lstm_ddos_service(model_path: str = None, **kwargs) -> LSTMDDoSDetectionService:
    """Get singleton LSTM DDoS service instance"""
    global lstm_ddos_service
    if lstm_ddos_service is None:
        lstm_ddos_service = LSTMDDoSDetectionService(model_path=model_path, **kwargs)
    return lstm_ddos_service

# Compatibility functions for integration
def analyze_ddos_lstm(traffic_data: pd.DataFrame, threshold: float = 0.5) -> Dict[str, Any]:
    """Analyze traffic data for DDoS using LSTM model"""
    service = get_lstm_ddos_service()
    return service.analyze_traffic_data(traffic_data, threshold)

def analyze_live_ddos(flows: List[Dict], threshold: float = 0.5) -> Dict[str, Any]:
    """Analyze live traffic flows for DDoS using LSTM model"""
    service = get_lstm_ddos_service()
    return service.analyze_live_traffic(flows, threshold)

def get_lstm_ddos_statistics() -> Dict[str, Any]:
    """Get LSTM DDoS detection statistics"""
    service = get_lstm_ddos_service()
    return service.get_statistics()

if __name__ == "__main__":
    print("🧪 Testing LSTM DDoS Detection Service")

    # Initialize service
    service = LSTMDDoSDetectionService()

    # Create sample traffic data
    sample_data = pd.DataFrame({
        'timestamp': pd.date_range(start='2025-01-01 10:00:00', periods=100, freq='100ms'),
        'src_ip': ['192.168.1.' + str(i % 10 + 1) for i in range(100)],
        'dst_ip': ['10.0.0.' + str(i % 5 + 1) for i in range(100)],
        'src_port': np.random.randint(1024, 65535, 100),
        'dst_port': [80, 443, 22, 3389, 445][np.random.randint(0, 5, 100)],
        'protocol': ['TCP'] * 100,
        'packets_count': np.random.randint(1, 1000, 100),
        'fwd_packets_count': np.random.randint(0, 500, 100),
        'bwd_packets_count': np.random.randint(0, 500, 100),
        'duration': np.random.uniform(0, 10, 100)
    })

    print(f"Created sample traffic data: {len(sample_data)} flows")

    # Analyze traffic
    result = service.analyze_traffic_data(sample_data)

    print("Analysis Results:")
    for key, value in result.items():
        if key != 'error':
            print(f"  {key}: {value}")

    # Get statistics
    stats = service.get_statistics()
    print("\nService Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
