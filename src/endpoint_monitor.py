#!/usr/bin/env python3
"""
Endpoint Request Monitor for Injection Detection
Monitors specific endpoints and analyzes all parameters for injection attacks
"""

from flask import Flask, request, jsonify, g
import time
import json
import threading
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from urllib.parse import parse_qs, unquote
import re
from collections import defaultdict

# Import production injection service
try:
    from production_injection_service import get_detector_instance, ProductionInjectionDetector
    INJECTION_SERVICE_AVAILABLE = True
except ImportError:
    print("Warning: Production injection service not available")
    INJECTION_SERVICE_AVAILABLE = False

class EndpointMonitor:
    """Monitor specific endpoints and analyze their parameters for injection attacks"""

    def __init__(self, 
                 detection_threshold: float = 0.5,
                 monitored_endpoints: List[str] = None,
                 monitor_all_endpoints: bool = False,
                 max_param_length: int = 10000,
                 enable_logging: bool = True):

        self.detection_threshold = detection_threshold
        self.monitored_endpoints = set(monitored_endpoints or [])
        self.monitor_all_endpoints = monitor_all_endpoints
        self.max_param_length = max_param_length
        self.enable_logging = enable_logging

        # Statistics
        self.total_requests_monitored = 0
        self.total_parameters_analyzed = 0
        self.injection_attempts_detected = 0
        self.endpoint_stats = defaultdict(lambda: {
            'request_count': 0,
            'param_count': 0,
            'injection_count': 0,
            'last_seen': None
        })

        # Thread safety
        self.lock = threading.RLock()

        # Alerts storage
        self.recent_alerts = []
        self.max_recent_alerts = 1000

        # Setup logging
        if enable_logging:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger('EndpointMonitor')
        else:
            self.logger = None

        # Get injection detector if available
        self.detector = None
        if INJECTION_SERVICE_AVAILABLE:
            try:
                self.detector = get_detector_instance()
                if self.logger:
                    self.logger.info("✅ Injection detector initialized for endpoint monitoring")
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to initialize detector: {e}")

        if self.logger:
            self.logger.info(f"🔍 Endpoint monitor initialized")
            self.logger.info(f"   Monitored endpoints: {list(self.monitored_endpoints) if not monitor_all_endpoints else 'ALL'}")
            self.logger.info(f"   Detection threshold: {detection_threshold}")

    def should_monitor_endpoint(self, endpoint: str, path: str) -> bool:
        """Check if endpoint should be monitored"""
        if self.monitor_all_endpoints:
            return True

        if endpoint in self.monitored_endpoints:
            return True

        # Check if path matches any monitored endpoints
        for monitored in self.monitored_endpoints:
            if path.startswith(monitored):
                return True

        return False

    def extract_parameters(self, request_obj) -> Dict[str, List[str]]:
        """Extract all parameters from request"""
        parameters = {}

        try:
            # Get query parameters
            if request_obj.args:
                for key in request_obj.args.keys():
                    values = request_obj.args.getlist(key)
                    parameters[f"query_{key}"] = values

            # Get form data
            if request_obj.form:
                for key in request_obj.form.keys():
                    values = request_obj.form.getlist(key)
                    parameters[f"form_{key}"] = values

            # Get JSON data
            if request_obj.is_json:
                json_data = request_obj.get_json(silent=True)
                if json_data:
                    if isinstance(json_data, dict):
                        self._extract_json_parameters(json_data, parameters)
                    else:
                        parameters['_json_root'] = [str(json_data)]

            # Get raw body as parameter if not JSON/form
            elif hasattr(request_obj, 'data') and request_obj.data:
                try:
                    body_text = request_obj.data.decode('utf-8', errors='ignore')
                    if body_text:
                        parameters['_raw_body'] = [body_text]
                except:
                    pass

            # Get headers (selective - common injection points)
            sensitive_headers = ['user-agent', 'referer', 'x-forwarded-for', 'authorization']
            for header_name in sensitive_headers:
                header_value = request_obj.headers.get(header_name)
                if header_value:
                    parameters[f'_header_{header_name.lower()}'] = [header_value]

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error extracting parameters: {e}")

        return parameters

    def _extract_json_parameters(self, json_obj: Any, parameters: Dict[str, List[str]], prefix: str = "") -> None:
        """Recursively extract parameters from JSON object"""
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                param_key = f"{prefix}.{key}" if prefix else f"json_{key}"
                if isinstance(value, (dict, list)):
                    self._extract_json_parameters(value, parameters, param_key)
                else:
                    str_value = str(value)
                    if param_key not in parameters:
                        parameters[param_key] = []
                    parameters[param_key].append(str_value)
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                param_key = f"{prefix}[{i}]" if prefix else f"json_item_{i}"
                if isinstance(item, (dict, list)):
                    self._extract_json_parameters(item, parameters, param_key)
                else:
                    str_value = str(item)
                    if param_key not in parameters:
                        parameters[param_key] = []
                    parameters[param_key].append(str_value)

    def analyze_parameters(self, parameters: Dict[str, List[str]], 
                          source_ip: str, endpoint: str, method: str) -> Dict[str, Any]:
        """Analyze extracted parameters for injection attacks"""

        analysis_results = {
            'total_parameters': 0,
            'analyzed_parameters': 0,
            'injection_detected': False,
            'injections_found': [],
            'parameter_results': {},
            'analysis_time_ms': 0,
            'detector_available': self.detector is not None
        }

        if not self.detector:
            return analysis_results

        start_time = time.time()

        try:
            for param_name, param_values in parameters.items():
                analysis_results['total_parameters'] += len(param_values)

                for i, param_value in enumerate(param_values):
                    # Skip very long parameters to avoid DoS
                    if len(param_value) > self.max_param_length:
                        if self.logger:
                            self.logger.warning(f"Skipping oversized parameter {param_name}: {len(param_value)} chars")
                        continue

                    analysis_results['analyzed_parameters'] += 1

                    # Perform injection detection
                    detection_result = self.detector.detect(param_value, self.detection_threshold)

                    param_key = f"{param_name}[{i}]" if len(param_values) > 1 else param_name
                    analysis_results['parameter_results'][param_key] = {
                        'value': param_value[:200] + "..." if len(param_value) > 200 else param_value,
                        'value_length': len(param_value),
                        'is_malicious': detection_result['is_malicious'],
                        'confidence': detection_result['confidence'],
                        'attack_type': detection_result.get('attack_type'),
                        'attack_confidence': detection_result.get('attack_confidence'),
                        'inference_time_ms': detection_result.get('inference_time_ms', 0),
                        'cache_hit': detection_result.get('cache_hit', False)
                    }

                    # If injection detected
                    if detection_result['is_malicious']:
                        analysis_results['injection_detected'] = True
                        injection_info = {
                            'parameter': param_key,
                            'value': param_value,
                            'confidence': detection_result['confidence'],
                            'attack_type': detection_result.get('attack_type'),
                            'attack_confidence': detection_result.get('attack_confidence')
                        }
                        analysis_results['injections_found'].append(injection_info)

                        # Create alert
                        alert = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'source_ip': source_ip,
                            'endpoint': endpoint,
                            'method': method,
                            'parameter': param_key,
                            'value': param_value[:500],  # Truncate for storage
                            'confidence': detection_result['confidence'],
                            'attack_type': detection_result.get('attack_type'),
                            'attack_confidence': detection_result.get('attack_confidence'),
                            'severity': self._calculate_severity(detection_result['confidence'])
                        }

                        with self.lock:
                            self.recent_alerts.append(alert)
                            if len(self.recent_alerts) > self.max_recent_alerts:
                                self.recent_alerts.pop(0)

                            self.injection_attempts_detected += 1

                        if self.logger:
                            self.logger.warning(
                                f"🚨 Injection detected in {endpoint} from {source_ip}: "
                                f"{param_key}='{param_value[:100]}...' "
                                f"(confidence: {detection_result['confidence']:.3f}, "
                                f"type: {detection_result.get('attack_type', 'unknown')})"
                            )

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error analyzing parameters: {e}")

        analysis_results['analysis_time_ms'] = (time.time() - start_time) * 1000
        return analysis_results

    def _calculate_severity(self, confidence: float) -> str:
        """Calculate severity based on confidence"""
        if confidence >= 0.9:
            return "critical"
        elif confidence >= 0.7:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def monitor_request(self, request_obj, endpoint_name: str = None) -> Dict[str, Any]:
        """Monitor a single request"""

        source_ip = request_obj.environ.get('HTTP_X_FORWARDED_FOR', request_obj.remote_addr or 'unknown')
        path = request_obj.path
        method = request_obj.method
        endpoint = endpoint_name or path

        # Check if should monitor
        if not self.should_monitor_endpoint(endpoint, path):
            return {'monitored': False, 'reason': 'endpoint_not_monitored'}

        monitor_start_time = time.time()

        # Extract parameters
        parameters = self.extract_parameters(request_obj)

        # Update statistics
        with self.lock:
            self.total_requests_monitored += 1
            self.total_parameters_analyzed += sum(len(values) for values in parameters.values())

            # Update endpoint stats
            self.endpoint_stats[endpoint]['request_count'] += 1
            self.endpoint_stats[endpoint]['param_count'] += sum(len(values) for values in parameters.values())
            self.endpoint_stats[endpoint]['last_seen'] = datetime.utcnow().isoformat()

        # Analyze parameters for injection
        analysis_results = self.analyze_parameters(parameters, source_ip, endpoint, method)

        if analysis_results['injection_detected']:
            with self.lock:
                self.endpoint_stats[endpoint]['injection_count'] += len(analysis_results['injections_found'])

        monitoring_time = (time.time() - monitor_start_time) * 1000

        # Compile monitoring results
        monitoring_results = {
            'monitored': True,
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': source_ip,
            'endpoint': endpoint,
            'path': path,
            'method': method,
            'monitoring_time_ms': monitoring_time,
            'parameters_extracted': len(parameters),
            'analysis': analysis_results
        }

        if self.logger and analysis_results['injection_detected']:
            self.logger.info(
                f"📊 Monitored {endpoint} from {source_ip}: "
                f"{len(parameters)} params, "
                f"{len(analysis_results['injections_found'])} injections detected"
            )

        return monitoring_results


# Global monitor instance
endpoint_monitor = None

def get_endpoint_monitor(detection_threshold: float = 0.5,
                        monitored_endpoints: List[str] = None,
                        monitor_all_endpoints: bool = False) -> EndpointMonitor:
    """Get singleton endpoint monitor instance"""
    global endpoint_monitor
    if endpoint_monitor is None:
        endpoint_monitor = EndpointMonitor(
            detection_threshold=detection_threshold,
            monitored_endpoints=monitored_endpoints,
            monitor_all_endpoints=monitor_all_endpoints
        )
    return endpoint_monitor


# Example monitored Flask app
def create_monitored_app():
    """Create Flask app with automatic endpoint monitoring"""

    app = Flask(__name__)

    # Initialize monitor with common endpoints
    monitor = get_endpoint_monitor(
        detection_threshold=0.5,
        monitored_endpoints=['/api/', '/admin/', '/login', '/search'],
        monitor_all_endpoints=False
    )

    @app.before_request
    def before_request_monitor():
        """Automatically monitor requests"""
        monitor = get_endpoint_monitor()

        # Check if current request should be monitored
        if monitor.should_monitor_endpoint(request.endpoint or '', request.path):
            try:
                monitoring_results = monitor.monitor_request(request)
                g.monitoring_results = monitoring_results

                # If injection detected, log it (optionally block)
                if monitoring_results.get('analysis', {}).get('injection_detected'):
                    app.logger.warning(f"Injection attack detected from {request.remote_addr}")

                    # Uncomment to block malicious requests:
                    # return jsonify({'error': 'Request blocked'}), 403

            except Exception as e:
                app.logger.error(f"Monitoring error: {e}")
                g.monitoring_results = {'error': str(e), 'monitored': False}

    # Example monitored endpoints
    @app.route('/api/users')
    def get_users():
        user_id = request.args.get('id', '')
        name = request.args.get('name', '')

        monitoring = getattr(g, 'monitoring_results', {})

        return jsonify({
            'users': [{'id': 1, 'name': 'John'}, {'id': 2, 'name': 'Jane'}],
            'monitoring': monitoring.get('analysis', {}) if monitoring else {}
        })

    @app.route('/api/search')
    def search():
        query = request.args.get('q', '')
        category = request.args.get('category', '')

        return jsonify({
            'query': query,
            'results': [],
            'monitoring': getattr(g, 'monitoring_results', {})
        })

    @app.route('/admin/config', methods=['POST'])
    def admin_config():
        config_data = request.get_json() or {}

        return jsonify({
            'status': 'updated',
            'monitoring': getattr(g, 'monitoring_results', {})
        })

    # Monitoring management endpoints
    @app.route('/monitor/stats')
    def monitor_stats():
        monitor = get_endpoint_monitor()
        with monitor.lock:
            return jsonify({
                'total_requests_monitored': monitor.total_requests_monitored,
                'total_parameters_analyzed': monitor.total_parameters_analyzed,
                'injection_attempts_detected': monitor.injection_attempts_detected,
                'monitored_endpoints': list(monitor.monitored_endpoints) if not monitor.monitor_all_endpoints else 'ALL',
                'monitor_all_endpoints': monitor.monitor_all_endpoints,
                'detection_threshold': monitor.detection_threshold,
                'recent_alerts_count': len(monitor.recent_alerts),
                'endpoint_statistics': dict(monitor.endpoint_stats),
                'detector_available': monitor.detector is not None
            })

    @app.route('/monitor/alerts')
    def monitor_alerts():
        monitor = get_endpoint_monitor()
        limit = request.args.get('limit', 100, type=int)

        with monitor.lock:
            alerts = monitor.recent_alerts[-limit:] if limit else monitor.recent_alerts.copy()

        return jsonify(alerts)

    return app


if __name__ == "__main__":
    print("🔍 Starting Endpoint Monitoring Demo")
    print("=" * 50)

    # Create and run monitored app
    app = create_monitored_app()

    print("Monitored endpoints:")
    print("  GET  /api/users?id=<value>&name=<value>")
    print("  GET  /api/search?q=<query>&category=<cat>")
    print("  POST /admin/config")
    print()
    print("Monitoring endpoints:")
    print("  GET  /monitor/stats - Get monitoring statistics")
    print("  GET  /monitor/alerts - Get recent alerts")
    print()
    print("Try injection attacks:")
    print("  curl 'http://localhost:5000/api/users?id=1\' OR \'1\'=\'1&name=admin'")
    print("  curl 'http://localhost:5000/api/search?q=<script>alert(1)</script>'")
    print("=" * 50)

    app.run(host='0.0.0.0', port=5000, debug=True)
