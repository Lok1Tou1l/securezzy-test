"""
Machine Learning-based Anomaly Detector
Replaces basic pattern matching with ML algorithms
"""

import numpy as np
import joblib
import os
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import redis
import json
import logging
from typing import Dict, List, Any, Tuple

class MLAnomalyDetector:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
        self.logger = logging.getLogger(__name__)

        # ML Models
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.text_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')

        # Model paths
        self.model_dir = 'models'
        os.makedirs(self.model_dir, exist_ok=True)

        # Feature cache
        self.feature_cache = {}

        # Initialize or load models
        self._initialize_models()

    def _initialize_models(self):
        """Initialize ML models for anomaly detection"""
        try:
            # Try to load existing models
            if os.path.exists(f'{self.model_dir}/isolation_forest.joblib'):
                self.isolation_forest = joblib.load(f'{self.model_dir}/isolation_forest.joblib')
                self.scaler = joblib.load(f'{self.model_dir}/scaler.joblib')
                self.text_vectorizer = joblib.load(f'{self.model_dir}/text_vectorizer.joblib')
                self.logger.info("Loaded existing ML models")
            else:
                # Create new models with default parameters
                self.isolation_forest = IsolationForest(
                    contamination=0.1,  # Expect 10% anomalies
                    random_state=42,
                    n_estimators=100
                )
                self.logger.info("Created new ML models")

        except Exception as e:
            self.logger.error(f"Error initializing ML models: {e}")
            # Fallback to basic models
            self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)

    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from security event"""
        features = []

        try:
            # Time-based features
            timestamp = datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
            features.extend([
                timestamp.hour,
                timestamp.minute,
                timestamp.weekday(),
                timestamp.day
            ])

            # Request features
            path = event.get('path', '')
            method = event.get('method', 'GET')
            body = event.get('body', '')
            user_agent = event.get('user_agent', '')

            # Path analysis
            features.extend([
                len(path),
                path.count('/'),
                path.count('?'),
                path.count('&'),
                path.count('='),
                1 if '..' in path else 0,
                1 if 'admin' in path.lower() else 0,
                1 if 'login' in path.lower() else 0
            ])

            # Method encoding
            method_encoding = {
                'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
                'HEAD': 5, 'OPTIONS': 6, 'PATCH': 7
            }
            features.append(method_encoding.get(method, 0))

            # Body analysis
            features.extend([
                len(body),
                body.count('<') + body.count('>'),  # HTML tags
                body.count("'") + body.count('"'),   # Quotes
                body.count('script'),
                body.count('select') + body.count('union') + body.count('drop')  # SQL keywords
            ])

            # User agent analysis
            features.extend([
                len(user_agent),
                1 if 'bot' in user_agent.lower() else 0,
                1 if 'crawler' in user_agent.lower() else 0,
                1 if 'curl' in user_agent.lower() else 0,
                1 if 'python' in user_agent.lower() else 0
            ])

            # IP-based features (from historical data)
            source_ip = event.get('source_ip', '0.0.0.0')
            ip_features = self._get_ip_behavioral_features(source_ip)
            features.extend(ip_features)

            # Headers analysis
            headers = event.get('headers', {})
            features.extend([
                len(headers),
                1 if 'X-Forwarded-For' in headers else 0,
                1 if 'Accept' not in headers else 0,  # Missing common headers
                1 if 'Referer' not in headers else 0
            ])

        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            # Return default feature vector
            features = [0] * 30

        # Ensure consistent feature vector size
        while len(features) < 30:
            features.append(0)

        return np.array(features[:30]).reshape(1, -1)

    def _get_ip_behavioral_features(self, source_ip: str) -> List[float]:
        """Extract behavioral features for IP address"""
        try:
            # Get historical data for this IP
            history_key = f"ip_behavior:{source_ip}"
            history_data = self.redis_client.hgetall(history_key)

            if not history_data:
                return [0.0] * 7  # Default values for new IPs

            # Calculate behavioral metrics
            total_requests = int(history_data.get('total_requests', 0))
            failed_requests = int(history_data.get('failed_requests', 0))
            unique_paths = len(history_data.get('unique_paths', '').split(','))
            avg_request_size = float(history_data.get('avg_request_size', 0))
            first_seen = datetime.fromisoformat(history_data.get('first_seen', datetime.utcnow().isoformat()))

            # Time since first seen (in hours)
            hours_active = (datetime.utcnow() - first_seen).total_seconds() / 3600

            features = [
                total_requests,
                failed_requests / max(total_requests, 1),  # Failure rate
                unique_paths,
                avg_request_size,
                hours_active,
                total_requests / max(hours_active, 1),  # Request rate per hour
                1.0 if total_requests > 1000 else 0.0  # High-volume flag
            ]

            return features

        except Exception as e:
            self.logger.error(f"Error getting IP behavioral features: {e}")
            return [0.0] * 7

    def update_ip_behavior(self, event: Dict[str, Any]):
        """Update behavioral tracking for IP address"""
        try:
            source_ip = event.get('source_ip')
            if not source_ip:
                return

            history_key = f"ip_behavior:{source_ip}"
            current_data = self.redis_client.hgetall(history_key)

            # Initialize or update metrics
            total_requests = int(current_data.get('total_requests', 0)) + 1
            failed_requests = int(current_data.get('failed_requests', 0))

            # Update failure count if this is a detected attack
            if event.get('threat_level') in ['high', 'medium']:
                failed_requests += 1

            # Track unique paths
            unique_paths = current_data.get('unique_paths', '').split(',')
            current_path = event.get('path', '')
            if current_path not in unique_paths:
                unique_paths.append(current_path)

            # Calculate average request size
            current_size = len(event.get('body', ''))
            prev_avg_size = float(current_data.get('avg_request_size', 0))
            new_avg_size = (prev_avg_size * (total_requests - 1) + current_size) / total_requests

            # Update Redis
            updated_data = {
                'total_requests': total_requests,
                'failed_requests': failed_requests,
                'unique_paths': ','.join(unique_paths[:100]),  # Limit to 100 paths
                'avg_request_size': new_avg_size,
                'last_seen': datetime.utcnow().isoformat()
            }

            # Set first_seen if not exists
            if not current_data.get('first_seen'):
                updated_data['first_seen'] = datetime.utcnow().isoformat()

            self.redis_client.hset(history_key, mapping=updated_data)
            self.redis_client.expire(history_key, 86400 * 30)  # 30 days

        except Exception as e:
            self.logger.error(f"Error updating IP behavior: {e}")

    def predict_anomaly(self, event: Dict[str, Any]) -> float:
        """Predict anomaly score for security event"""
        try:
            # Extract features
            features = self.extract_features(event)

            # Scale features
            if hasattr(self.scaler, 'mean_'):
                features_scaled = self.scaler.transform(features)
            else:
                # If scaler not fitted, fit with current features and some defaults
                default_features = np.zeros((10, features.shape[1]))
                default_features[0] = features[0]
                self.scaler.fit(default_features)
                features_scaled = self.scaler.transform(features)

            # Predict anomaly
            if hasattr(self.isolation_forest, 'decision_function'):
                # Get anomaly score (-1 to 1, where negative is anomalous)
                anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
                # Convert to 0-1 scale (1 = most anomalous)
                normalized_score = max(0, (1 - anomaly_score) / 2)
            else:
                # Fit model if not trained
                self._train_with_current_event(features_scaled)
                normalized_score = 0.5  # Neutral score for untrained model

            # Update IP behavioral data
            self.update_ip_behavior(event)

            return min(1.0, max(0.0, normalized_score))

        except Exception as e:
            self.logger.error(f"Error predicting anomaly: {e}")
            return 0.5  # Neutral score on error

    def _train_with_current_event(self, features: np.ndarray):
        """Train model with current event (for initial training)"""
        try:
            # Generate some synthetic normal data for initial training
            synthetic_data = []
            base_features = features[0]

            # Create variations of current features
            for _ in range(100):
                variation = base_features.copy()
                # Add small random variations
                noise = np.random.normal(0, 0.1, len(variation))
                variation = variation + noise
                synthetic_data.append(variation)

            synthetic_array = np.array(synthetic_data)

            # Fit scaler and model
            self.scaler.fit(synthetic_array)
            self.isolation_forest.fit(synthetic_array)

            self.logger.info("Trained ML model with synthetic data")

        except Exception as e:
            self.logger.error(f"Error training model: {e}")

    def retrain_model(self, training_events: List[Dict[str, Any]]):
        """Retrain model with new data"""
        try:
            if len(training_events) < 50:
                self.logger.warning("Insufficient data for retraining")
                return False

            # Extract features from all events
            feature_matrix = []
            for event in training_events:
                features = self.extract_features(event)
                feature_matrix.append(features[0])

            feature_array = np.array(feature_matrix)

            # Retrain scaler and model
            self.scaler.fit(feature_array)
            scaled_features = self.scaler.transform(feature_array)

            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(scaled_features)

            # Save models
            self._save_models()

            self.logger.info(f"Retrained model with {len(training_events)} events")
            return True

        except Exception as e:
            self.logger.error(f"Error retraining model: {e}")
            return False

    def _save_models(self):
        """Save trained models to disk"""
        try:
            joblib.dump(self.isolation_forest, f'{self.model_dir}/isolation_forest.joblib')
            joblib.dump(self.scaler, f'{self.model_dir}/scaler.joblib')
            joblib.dump(self.text_vectorizer, f'{self.model_dir}/text_vectorizer.joblib')
            self.logger.info("Saved ML models to disk")
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance for model interpretation"""
        try:
            # For Isolation Forest, we can't directly get feature importance
            # But we can analyze which features contribute most to anomalies
            feature_names = [
                'hour', 'minute', 'weekday', 'day',
                'path_length', 'path_slashes', 'path_questions', 'path_ampersands',
                'path_equals', 'path_traversal', 'path_admin', 'path_login',
                'method_encoded', 'body_length', 'html_tags', 'quotes',
                'script_count', 'sql_keywords', 'ua_length', 'ua_bot',
                'ua_crawler', 'ua_curl', 'ua_python', 'ip_total_requests',
                'ip_failure_rate', 'ip_unique_paths', 'ip_avg_size',
                'ip_hours_active', 'ip_request_rate', 'ip_high_volume'
            ]

            # Return equal importance for now (could be enhanced with SHAP values)
            importance = {name: 1.0/len(feature_names) for name in feature_names}
            return importance

        except Exception as e:
            self.logger.error(f"Error calculating feature importance: {e}")
            return {}
