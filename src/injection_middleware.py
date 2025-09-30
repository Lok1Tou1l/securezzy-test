"""
Flask Middleware for Automatic Injection Detection
Easy integration with existing Flask applications
"""

from flask import request, g, jsonify
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

try:
    from endpoint_monitor import EndpointMonitor, get_endpoint_monitor
    MONITOR_AVAILABLE = True
except ImportError:
    print("Warning: Endpoint monitor not available")
    MONITOR_AVAILABLE = False

class InjectionDetectionMiddleware:
    """
    Flask middleware for automatic injection detection on all requests
    Easy to integrate with existing applications
    """

    def __init__(self, 
                 app=None,
                 detection_threshold: float = 0.5,
                 monitored_endpoints: List[str] = None,
                 monitor_all_endpoints: bool = True,
                 block_attacks: bool = False,
                 log_attacks: bool = True,
                 include_monitoring_headers: bool = True):

        self.detection_threshold = detection_threshold
        self.monitored_endpoints = monitored_endpoints or []
        self.monitor_all_endpoints = monitor_all_endpoints
        self.block_attacks = block_attacks
        self.log_attacks = log_attacks
        self.include_monitoring_headers = include_monitoring_headers

        self.monitor = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize middleware with Flask app"""

        if not MONITOR_AVAILABLE:
            app.logger.warning("Injection detection monitor not available")
            return

        # Initialize monitor
        self.monitor = get_endpoint_monitor(
            detection_threshold=self.detection_threshold,
            monitored_endpoints=self.monitored_endpoints,
            monitor_all_endpoints=self.monitor_all_endpoints
        )

        # Register middleware
        app.before_request(self._before_request)
        app.after_request(self._after_request)

        # Add monitoring endpoints
        self._add_monitoring_endpoints(app)

        app.logger.info("✅ Injection detection middleware initialized")

    def _before_request(self):
        """Process request before route handler"""

        if not self.monitor:
            return

        try:
            # Monitor the request
            monitoring_results = self.monitor.monitor_request(request)
            g.injection_monitoring = monitoring_results

            # Check for injection attacks
            if monitoring_results.get('analysis', {}).get('injection_detected'):
                injections = monitoring_results['analysis']['injections_found']

                if self.log_attacks:
                    for injection in injections:
                        print(f"🚨 INJECTION ATTACK DETECTED:")
                        print(f"   Source: {monitoring_results.get('source_ip')}")
                        print(f"   Endpoint: {monitoring_results.get('endpoint')}")
                        print(f"   Parameter: {injection['parameter']}")
                        print(f"   Value: {injection['value'][:100]}...")
                        print(f"   Attack Type: {injection.get('attack_type', 'unknown')}")
                        print(f"   Confidence: {injection['confidence']:.3f}")
                        print()

                # Block attack if enabled
                if self.block_attacks:
                    return jsonify({
                        'error': 'Request blocked due to security violation',
                        'details': 'Potential injection attack detected',
                        'timestamp': datetime.utcnow().isoformat()
                    }), 403

        except Exception as e:
            print(f"Injection monitoring error: {e}")
            g.injection_monitoring = {'error': str(e), 'monitored': False}

    def _after_request(self, response):
        """Process response after route handler"""

        if not self.include_monitoring_headers:
            return response

        monitoring_results = getattr(g, 'injection_monitoring', {})

        if monitoring_results.get('monitored'):
            # Add monitoring headers
            response.headers['X-Injection-Monitored'] = 'true'
            response.headers['X-Parameters-Analyzed'] = str(monitoring_results.get('parameters_extracted', 0))

            if monitoring_results.get('analysis', {}).get('injection_detected'):
                response.headers['X-Injection-Detected'] = 'true'
                response.headers['X-Injection-Count'] = str(len(monitoring_results['analysis']['injections_found']))
            else:
                response.headers['X-Injection-Detected'] = 'false'

        return response

    def _add_monitoring_endpoints(self, app):
        """Add monitoring endpoints to the app"""

        @app.route('/_monitor/stats')
        def _monitor_stats():
            """Get injection monitoring statistics"""
            if not self.monitor:
                return jsonify({'error': 'Monitor not available'}), 503

            with self.monitor.lock:
                return jsonify({
                    'total_requests_monitored': self.monitor.total_requests_monitored,
                    'total_parameters_analyzed': self.monitor.total_parameters_analyzed,
                    'injection_attempts_detected': self.monitor.injection_attempts_detected,
                    'monitored_endpoints': list(self.monitor.monitored_endpoints) if not self.monitor.monitor_all_endpoints else 'ALL',
                    'monitor_all_endpoints': self.monitor.monitor_all_endpoints,
                    'detection_threshold': self.monitor.detection_threshold,
                    'recent_alerts_count': len(self.monitor.recent_alerts),
                    'detector_available': self.monitor.detector is not None,
                    'middleware_config': {
                        'block_attacks': self.block_attacks,
                        'log_attacks': self.log_attacks,
                        'include_monitoring_headers': self.include_monitoring_headers
                    }
                })

        @app.route('/_monitor/alerts')
        def _monitor_alerts():
            """Get recent injection alerts"""
            if not self.monitor:
                return jsonify({'error': 'Monitor not available'}), 503

            limit = request.args.get('limit', 100, type=int)

            with self.monitor.lock:
                alerts = self.monitor.recent_alerts[-limit:] if limit else self.monitor.recent_alerts.copy()

            return jsonify(alerts)

        @app.route('/_monitor/config', methods=['POST'])
        def _monitor_config():
            """Update monitoring configuration"""
            if not self.monitor:
                return jsonify({'error': 'Monitor not available'}), 503

            config = request.get_json() or {}

            if 'threshold' in config:
                self.detection_threshold = float(config['threshold'])
                self.monitor.detection_threshold = self.detection_threshold

            if 'block_attacks' in config:
                self.block_attacks = bool(config['block_attacks'])

            if 'log_attacks' in config:
                self.log_attacks = bool(config['log_attacks'])

            return jsonify({
                'message': 'Configuration updated',
                'config': {
                    'threshold': self.detection_threshold,
                    'block_attacks': self.block_attacks,
                    'log_attacks': self.log_attacks
                }
            })


# Decorator for easy endpoint-specific monitoring
def monitor_injection(threshold: float = None, 
                     block_on_detection: bool = None,
                     custom_response: Dict = None):
    """
    Decorator for endpoint-specific injection monitoring

    Args:
        threshold: Custom detection threshold for this endpoint
        block_on_detection: Whether to block requests with injection
        custom_response: Custom response for blocked requests
    """

    def decorator(f):
        def wrapper(*args, **kwargs):

            # Get monitoring results from middleware
            monitoring_results = getattr(g, 'injection_monitoring', {})

            # Check for injection with custom threshold
            if threshold is not None and monitoring_results.get('monitored'):
                # Re-analyze with custom threshold if needed
                from endpoint_monitor import get_endpoint_monitor
                monitor = get_endpoint_monitor()

                if monitor and monitor.detector:
                    # Quick re-check with custom threshold
                    parameters = monitor.extract_parameters(request)
                    injection_detected = False

                    for param_name, param_values in parameters.items():
                        for param_value in param_values:
                            if len(param_value) <= monitor.max_param_length:
                                result = monitor.detector.detect(param_value, threshold)
                                if result['is_malicious']:
                                    injection_detected = True
                                    break
                        if injection_detected:
                            break

                    # Block if custom blocking enabled
                    if block_on_detection and injection_detected:
                        if custom_response:
                            return jsonify(custom_response), 403
                        else:
                            return jsonify({
                                'error': 'Access denied',
                                'reason': 'Security violation detected'
                            }), 403

            # Call original function
            result = f(*args, **kwargs)

            # Add monitoring info to response if it's JSON
            if isinstance(result, tuple) and len(result) >= 2:
                response_data, status_code = result[0], result[1]
            else:
                response_data, status_code = result, 200

            # If response is JSON, add monitoring info
            if hasattr(response_data, 'get_json'):
                try:
                    json_data = response_data.get_json()
                    if isinstance(json_data, dict):
                        json_data['_monitoring'] = monitoring_results.get('analysis', {})
                        return jsonify(json_data), status_code
                except:
                    pass

            return result

        wrapper.__name__ = f.__name__
        return wrapper

    return decorator


# Example integration with existing Flask app
def demo_existing_app():
    """Demo of integrating with existing Flask app"""

    app = Flask(__name__)

    # Initialize injection detection middleware
    injection_middleware = InjectionDetectionMiddleware(
        app,
        detection_threshold=0.5,
        monitor_all_endpoints=True,
        block_attacks=False,  # Set to True to block attacks
        log_attacks=True,
        include_monitoring_headers=True
    )

    # Your existing routes work normally
    @app.route('/')
    def index():
        return jsonify({'message': 'Welcome to the API'})

    @app.route('/api/users')
    def get_users():
        user_id = request.args.get('id', '')
        name = request.args.get('name', '')

        return jsonify({
            'users': [
                {'id': 1, 'name': 'Alice'},
                {'id': 2, 'name': 'Bob'}
            ],
            'filters': {
                'id': user_id,
                'name': name
            }
        })

    @app.route('/api/search')
    @monitor_injection(threshold=0.3, block_on_detection=True)  # Custom monitoring
    def search():
        query = request.args.get('q', '')

        # This endpoint will block attacks with threshold 0.3
        return jsonify({
            'query': query,
            'results': [
                {'title': 'Result 1', 'url': '/item/1'},
                {'title': 'Result 2', 'url': '/item/2'}
            ]
        })

    @app.route('/admin/users', methods=['POST'])
    @monitor_injection(
        threshold=0.2,  # Very sensitive
        block_on_detection=True,
        custom_response={'error': 'Admin access denied', 'code': 'SECURITY_VIOLATION'}
    )
    def admin_users():
        data = request.get_json() or {}

        return jsonify({
            'message': 'User created',
            'user_id': 123
        })

    return app

