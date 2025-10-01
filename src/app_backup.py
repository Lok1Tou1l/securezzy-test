from flask import Flask, jsonify, request, send_from_directory, g
from flask import make_response
import json
from queue import Queue, Empty
from typing import List, Any, Dict, Optional
import time
import threading
import logging
from datetime import datetime
from urllib.parse import parse_qs, unquote
import re
from collections import defaultdict
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from storage import (
        event_store,
        ddos_alert_store,
        injection_alert_store,
        log_store,
        LogType,
        LogLevel,
        log_info,
        log_warning,
        log_error,
        log_critical,
        log_debug
    )
    STORAGE_AVAILABLE = True
except ImportError:
    print("Warning: Storage modules not available")
    STORAGE_AVAILABLE = False
    # Create mock stores
    class MockStore:
        def __init__(self):
            self.data = []
        def add(self, item):
            self.data.append(item)
        def get_all(self):
            return self.data

    event_store = MockStore()
    ddos_alert_store = MockStore()
    injection_alert_store = MockStore()
    log_store = MockStore()
    
    # Mock logging functions
    def log_info(message, log_type=None, source="system", details=None):
        print(f"INFO: {message}")
    def log_warning(message, log_type=None, source="system", details=None):
        print(f"WARNING: {message}")
    def log_error(message, log_type=None, source="system", details=None):
        print(f"ERROR: {message}")
    def log_critical(message, log_type=None, source="system", details=None):
        print(f"CRITICAL: {message}")
    def log_debug(message, log_type=None, source="system", details=None):
        print(f"DEBUG: {message}")

try:
    from detection.ddos import record_request as ddos_record_request, is_ddos, analyze_ddos_threat
    DDOS_AVAILABLE = True
except ImportError:
    print("Warning: DDoS detection not available")
    DDOS_AVAILABLE = False
    def ddos_record_request(*args, **kwargs): pass
    def is_ddos(*args): return False
    def analyze_ddos_threat(*args): return {"confidence": 0.0, "severity": "none", "threats": [], "recommendations": []}

try:
    from detection.injection import has_injection_signature, analyze_injection_signature
    INJECTION_AVAILABLE = True
except ImportError:
    print("Warning: Injection detection not available")
    INJECTION_AVAILABLE = False
    def has_injection_signature(*args): return False
    def analyze_injection_signature(*args): return {"has_injection": False, "confidence": 0.0, "severity": "none", "details": []}

try:
    from detection.whitelist import is_whitelisted, whitelist_manager
    WHITELIST_AVAILABLE = True
except ImportError:
    print("Warning: Whitelist not available")
    WHITELIST_AVAILABLE = False
    def is_whitelisted(*args): return (False, 0.0, "Whitelist not available")
    class MockWhitelistManager:
        def get_statistics(self): return {}
        def add_ip_whitelist(self, *args): return True
        def add_pattern_whitelist(self, *args): return True
        def remove_whitelist(self, *args): return True
    whitelist_manager = MockWhitelistManager()

try:
    from sniffer import run_sniffer
    SNIFFER_AVAILABLE = True
except ImportError:
    print("Warning: Sniffer not available")
    SNIFFER_AVAILABLE = False
    def run_sniffer(*args, **kwargs): pass

# Optional enhanced detectors
try:
    from new.detection_engine import DetectionEngine
    from new.ml_detector import MLAnomalyDetector
    ENHANCED_DETECTORS_AVAILABLE = True
except Exception:
    DetectionEngine = None
    MLAnomalyDetector = None
    ENHANCED_DETECTORS_AVAILABLE = False

# LSTM DDoS Detection Service
try:
    from lstm_ddos_service import get_lstm_ddos_service, analyze_live_ddos
    LSTM_DDOS_AVAILABLE = True
    print("✅ LSTM DDoS service available")
except ImportError as e:
    print(f"Warning: LSTM DDoS service not available: {e}")
    LSTM_DDOS_AVAILABLE = False
    get_lstm_ddos_service = None
    analyze_live_ddos = None

# Optional production injection service
try:
    from production_injection_service import get_detector_instance, ProductionInjectionDetector
    INJECTION_SERVICE_AVAILABLE = True
    print("✅ Production injection service available")
except ImportError:
    print("Warning: Production injection service not available")
    INJECTION_SERVICE_AVAILABLE = False

from dotenv import load_dotenv

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
            if hasattr(request_obj, 'args') and request_obj.args:
                for key in request_obj.args.keys():
                    values = request_obj.args.getlist(key)
                    parameters[f"query_{key}"] = values

            # Get form data
            if hasattr(request_obj, 'form') and request_obj.form:
                for key in request_obj.form.keys():
                    values = request_obj.form.getlist(key)
                    parameters[f"form_{key}"] = values

            # Get JSON data
            if hasattr(request_obj, 'is_json') and request_obj.is_json:
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
            if hasattr(request_obj, 'headers'):
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

        source_ip = getattr(request_obj, 'remote_addr', 'unknown') or 'unknown'
        if hasattr(request_obj, 'environ'):
            source_ip = request_obj.environ.get('HTTP_X_FORWARDED_FOR', source_ip)

        path = getattr(request_obj, 'path', '/')
        method = getattr(request_obj, 'method', 'GET')
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

        if not INJECTION_SERVICE_AVAILABLE:
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


def create_app() -> Flask:
    app = Flask(__name__, static_folder='../frontend', static_url_path='')

    # Initialize injection detection middleware
    if INJECTION_SERVICE_AVAILABLE:
    injection_middleware = InjectionDetectionMiddleware(
        app,
        detection_threshold=0.5,
        monitored_endpoints=['/api/', '/admin/', '/login', '/search', '/events', '/analyze'],
        monitor_all_endpoints=False,
        block_attacks=False,  # Set to True to block attacks
        log_attacks=True,
        include_monitoring_headers=True
    )
        print("✅ Injection detection middleware initialized")
    else:
        print("⚠️ Injection detection middleware not available")

    # Simple in-process pub/sub for Server-Sent Events (SSE)
    subscribers: List[Queue] = []

    def publish(event_dict: Dict[str, Any]) -> None:
        for q in list(subscribers):
            try:
                q.put_nowait(event_dict)
            except Exception:
                # Best effort; drop if queue is closed
                pass

    @app.route("/stream/events", methods=['GET'])
    def stream_events() -> Any:
        def gen():
            q: Queue = Queue(maxsize=100)
            subscribers.append(q)
            try:
                # Initial comment to open stream
                yield ": connected\n\n"
                while True:
                    try:
                        item = q.get(timeout=15)
                        data = json.dumps(item)
                        yield f"data: {data}\n\n"
                    except Empty:
                        # Keep-alive comment every 15s
                        yield ": keepalive\n\n"
            finally:
                try:
                    subscribers.remove(q)
                except ValueError:
                    pass

        resp = make_response(gen())
        resp.headers["Content-Type"] = "text/event-stream"
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Connection"] = "keep-alive"
        return resp

    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    @app.route("/events", methods=["OPTIONS"])  # Preflight for POST /events
    def events_options() -> Any:
        resp = make_response("", 204)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    @app.route("/")
    def index() -> Any:
        return send_from_directory('../frontend', 'web.html')
    
    @app.route("/dashboard")
    def dashboard() -> Any:
        return send_from_directory('../frontend', 'web.html')
    
    @app.route("/legacy")
    def legacy_index() -> Any:
        return send_from_directory('../frontend', 'index.html')
    

    @app.route("/health", methods=['GET'])
    def health() -> Any:
        """Enhanced health check with service status"""
        health_data = {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "storage": STORAGE_AVAILABLE,
                "ddos_detection": DDOS_AVAILABLE,
                "injection_detection": INJECTION_AVAILABLE,
                "whitelist": WHITELIST_AVAILABLE,
                "sniffer": SNIFFER_AVAILABLE,
                "production_injection": INJECTION_SERVICE_AVAILABLE,
                "enhanced_detectors": ENHANCED_DETECTORS_AVAILABLE
            }
        }

        # Add endpoint monitoring status
        if INJECTION_SERVICE_AVAILABLE:
            try:
                monitor = get_endpoint_monitor()
                health_data["endpoint_monitoring"] = {
                    "enabled": True,
                    "requests_monitored": monitor.total_requests_monitored,
                    "injection_attempts": monitor.injection_attempts_detected,
                    "detector_available": monitor.detector is not None
                }
            except Exception as e:
                health_data["endpoint_monitoring"] = {"enabled": False, "error": str(e)}
        else:
            health_data["endpoint_monitoring"] = {"enabled": False}

        return jsonify(health_data), 200

    @app.route("/events", methods=['GET'])
    def list_events() -> Any:
        return jsonify(event_store.get_all()), 200

    @app.route("/alerts/ddos", methods=['GET'])
    def list_ddos_alerts() -> Any:
        return jsonify(ddos_alert_store.get_all()), 200

    @app.route("/alerts/injection", methods=['GET'])
    def list_injection_alerts() -> Any:
        return jsonify(injection_alert_store.get_all()), 200

    @app.route("/whitelist", methods=['GET'])
    def get_whitelist() -> Any:
        """Get whitelist statistics and entries."""
        return jsonify(whitelist_manager.get_statistics()), 200

    @app.route("/whitelist/ip", methods=['POST'])
    def add_ip_whitelist() -> Any:
        """Add IP to whitelist."""
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        ip: str = payload.get("ip", "")
        reason: str = payload.get("reason", "Manual whitelist")
        confidence: float = payload.get("confidence", 1.0)
        expires_at: Optional[float] = payload.get("expires_at")
        
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        
        success = whitelist_manager.add_ip_whitelist(ip, reason, confidence, expires_at)
        if success:
            return jsonify({"message": f"IP {ip} added to whitelist"}), 201
        else:
            return jsonify({"error": "Invalid IP address"}), 400

    @app.route("/whitelist/pattern", methods=['POST'])
    def add_pattern_whitelist() -> Any:
        """Add pattern to whitelist."""
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        pattern: str = payload.get("pattern", "")
        reason: str = payload.get("reason", "Manual pattern whitelist")
        confidence: float = payload.get("confidence", 1.0)
        expires_at: Optional[float] = payload.get("expires_at")
        
        if not pattern:
            return jsonify({"error": "Pattern is required"}), 400
        
        success = whitelist_manager.add_pattern_whitelist(pattern, reason, confidence, expires_at)
        if success:
            return jsonify({"message": f"Pattern {pattern} added to whitelist"}), 201
        else:
            return jsonify({"error": "Invalid regex pattern"}), 400

    @app.route("/whitelist/<value>", methods=['DELETE'])
    def remove_whitelist_entry(value: str) -> Any:
        """Remove whitelist entry."""
        success = whitelist_manager.remove_whitelist(value)
        if success:
            return jsonify({"message": f"Whitelist entry {value} removed"}), 200
        else:
            return jsonify({"error": "Whitelist entry not found"}), 404

    @app.route("/analytics/injection", methods=['GET'])
    def get_injection_analytics() -> Any:
        """Get injection detection analytics."""
        if INJECTION_AVAILABLE:
            try:
        from detection.injection import get_injection_statistics
                stats = get_injection_statistics()
            except:
                stats = {"total_detections": 0, "error": "Statistics not available"}
        else:
            stats = {"total_detections": 0, "error": "Injection detection not available"}

        # Add endpoint monitoring stats if available
        if INJECTION_SERVICE_AVAILABLE:
            try:
                monitor = get_endpoint_monitor()
                stats["endpoint_monitoring"] = {
                    "requests_monitored": monitor.total_requests_monitored,
                    "parameters_analyzed": monitor.total_parameters_analyzed,
                    "injection_attempts": monitor.injection_attempts_detected
                }
            except Exception as e:
                stats["endpoint_monitoring"] = {"error": str(e)}

        return jsonify(stats), 200

    @app.route("/analytics/ddos", methods=['GET'])
    def get_ddos_analytics() -> Any:
        """Get DDoS detection analytics."""
        if DDOS_AVAILABLE:
            try:
        from detection.ddos import get_ddos_statistics
        return jsonify(get_ddos_statistics()), 200
            except:
                return jsonify({"error": "DDoS statistics not available"}), 503
        else:
            return jsonify({"error": "DDoS detection not available"}), 503

    # Monitoring endpoints
    @app.route("/monitor/stats", methods=['GET'])
    def monitor_stats() -> Any:
        """Get injection monitoring statistics"""
        if not INJECTION_SERVICE_AVAILABLE:
            return jsonify({"error": "Monitoring not available"}), 503

        try:
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
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/monitor/alerts", methods=['GET'])
    def monitor_alerts() -> Any:
        """Get recent injection alerts"""
        if not INJECTION_SERVICE_AVAILABLE:
            return jsonify({"error": "Monitoring not available"}), 503

        try:
        monitor = get_endpoint_monitor()
        limit = request.args.get('limit', 100, type=int)

        with monitor.lock:
            alerts = monitor.recent_alerts[-limit:] if limit else monitor.recent_alerts.copy()

        return jsonify(alerts), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/monitor/config", methods=['POST'])
    def monitor_config() -> Any:
        """Update monitoring configuration"""
        if not INJECTION_SERVICE_AVAILABLE:
            return jsonify({"error": "Monitoring not available"}), 503

        try:
        monitor = get_endpoint_monitor()
        config = request.get_json() or {}

        if 'threshold' in config:
            monitor.detection_threshold = float(config['threshold'])

        if 'monitored_endpoints' in config:
            monitor.monitored_endpoints = set(config['monitored_endpoints'])

        if 'monitor_all_endpoints' in config:
            monitor.monitor_all_endpoints = bool(config['monitor_all_endpoints'])

        return jsonify({
            'message': 'Configuration updated',
            'config': {
                'threshold': monitor.detection_threshold,
                'monitored_endpoints': list(monitor.monitored_endpoints),
                'monitor_all_endpoints': monitor.monitor_all_endpoints
            }
        }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Sniffer management endpoints
    @app.route("/sniffer/status", methods=['GET'])
    def sniffer_status() -> Any:
        """Get sniffer status and configuration"""
        return jsonify({
            'available': SNIFFER_AVAILABLE,
            'enabled': os.environ.get("SECUREZZY_SNIFFER_ENABLED", "true").lower() in {"1", "true", "yes"},
            'interface': os.environ.get("SECUREZZY_IFACE", "auto"),
            'bpf_filter': os.environ.get("SECUREZZY_BPF", "tcp port 80 or tcp port 443"),
            'api_base': os.environ.get("SECUREZZY_API", "http://127.0.0.1:5000")
        }), 200

    @app.route("/sniffer/config", methods=['POST'])
    def sniffer_config() -> Any:
        """Update sniffer configuration"""
        if not SNIFFER_AVAILABLE:
            return jsonify({"error": "Sniffer not available"}), 503

        try:
            config = request.get_json() or {}
            
            # Update environment variables (these will take effect on next restart)
            if 'enabled' in config:
                os.environ["SECUREZZY_SNIFFER_ENABLED"] = str(config['enabled']).lower()
            
            if 'interface' in config:
                os.environ["SECUREZZY_IFACE"] = config['interface'] or ""
            
            if 'bpf_filter' in config:
                os.environ["SECUREZZY_BPF"] = config['bpf_filter']
            
            if 'api_base' in config:
                os.environ["SECUREZZY_API"] = config['api_base']

            return jsonify({
                'message': 'Sniffer configuration updated (restart required for changes)',
                'config': {
                    'enabled': os.environ.get("SECUREZZY_SNIFFER_ENABLED", "true"),
                    'interface': os.environ.get("SECUREZZY_IFACE", ""),
                    'bpf_filter': os.environ.get("SECUREZZY_BPF", "tcp port 80 or tcp port 443"),
                    'api_base': os.environ.get("SECUREZZY_API", "http://127.0.0.1:5000")
                }
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/sniffer/interfaces", methods=['GET'])
    def sniffer_interfaces() -> Any:
        """Get available network interfaces for sniffing"""
        if not SNIFFER_AVAILABLE:
            return jsonify({"error": "Sniffer not available"}), 503

        try:
            import psutil
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        interfaces.append({
                            'name': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
                        break
            return jsonify({'interfaces': interfaces}), 200
        except ImportError:
            return jsonify({'interfaces': [{'name': 'auto', 'ip': 'auto', 'netmask': 'auto'}]}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # LSTM DDoS Service endpoints
    @app.route("/ddos/lstm/status", methods=['GET'])
    def lstm_ddos_status() -> Any:
        """Get LSTM DDoS service status and statistics"""
        if not LSTM_DDOS_AVAILABLE:
            return jsonify({"error": "LSTM DDoS service not available"}), 503

        try:
            from lstm_ddos_service import get_lstm_ddos_statistics
            stats = get_lstm_ddos_statistics()
            return jsonify({
                'available': True,
                'statistics': stats
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/ddos/lstm/analyze", methods=['POST'])
    def lstm_ddos_analyze() -> Any:
        """Analyze traffic data with LSTM DDoS service"""
        if not LSTM_DDOS_AVAILABLE:
            return jsonify({"error": "LSTM DDoS service not available"}), 503

        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            threshold = data.get('threshold', 0.5)
            flows = data.get('flows', [])
            
            if not flows:
                return jsonify({"error": "No flows provided"}), 400

            result = analyze_live_ddos(flows, threshold)
            return jsonify(result), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/ddos/lstm/alerts", methods=['GET'])
    def lstm_ddos_alerts() -> Any:
        """Get recent DDoS alerts"""
        if not LSTM_DDOS_AVAILABLE:
            return jsonify({"error": "LSTM DDoS service not available"}), 503

        try:
            # Get recent DDoS events from storage
            if STORAGE_AVAILABLE and event_store:
                try:
                    events = event_store.get_events(event_type='ddos_attack', limit=20)
                    alerts = []
                    for event in events:
                        alerts.append({
                            'timestamp': event.get('timestamp', time.time()),
                            'source_ip': event.get('source_ip', 'unknown'),
                            'attack_probability': event.get('attack_probability', 0.0),
                            'attack_intensity': event.get('attack_intensity', 0.0),
                            'confidence': event.get('confidence', 0.0),
                            'details': event.get('details', {})
                        })
                    return jsonify({'alerts': alerts}), 200
                except Exception as e:
                    print(f"Error getting DDoS events: {e}")
                    return jsonify({'alerts': []}), 200
            else:
                return jsonify({'alerts': []}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Logging endpoints
    @app.route("/logs", methods=['GET'])
    def get_logs() -> Any:
        """Get logs with optional filtering"""
        if not STORAGE_AVAILABLE:
            return jsonify({"error": "Logging not available"}), 503

        try:
            log_type = request.args.get('type')
            level = request.args.get('level')
            source = request.args.get('source')
            limit = request.args.get('limit', type=int)
            
            logs = log_store.get_logs(log_type=log_type, level=level, source=source, limit=limit)
            return jsonify({'logs': logs}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/logs/statistics", methods=['GET'])
    def get_log_statistics() -> Any:
        """Get log statistics"""
        if not STORAGE_AVAILABLE:
            return jsonify({"error": "Logging not available"}), 503

        try:
            stats = log_store.get_log_statistics()
            return jsonify(stats), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/logs/clear", methods=['POST'])
    def clear_logs() -> Any:
        """Clear all logs"""
        if not STORAGE_AVAILABLE:
            return jsonify({"error": "Logging not available"}), 503

        try:
            log_store.clear_logs()
            log_info("Logs cleared by user", LogType.SYSTEM, "api")
            return jsonify({'message': 'Logs cleared successfully'}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/logs/export", methods=['GET'])
    def export_logs() -> Any:
        """Export logs as JSON"""
        if not STORAGE_AVAILABLE:
            return jsonify({"error": "Logging not available"}), 503

        try:
            log_type = request.args.get('type')
            level = request.args.get('level')
            source = request.args.get('source')
            limit = request.args.get('limit', type=int)
            
            logs = log_store.get_logs(log_type=log_type, level=level, source=source, limit=limit)
            
            response = make_response(json.dumps(logs, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=logs_{int(time.time())}.json'
            
            log_info(f"Logs exported: {len(logs)} entries", LogType.SYSTEM, "api")
            return response
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Example monitored endpoints to demonstrate functionality
    @app.route('/api/users')
    def get_users() -> Any:
        """Example endpoint that will be monitored for injection attacks"""
        user_id = request.args.get('id', '')
        name = request.args.get('name', '')

        # Get monitoring results if available
        monitoring = getattr(g, 'injection_monitoring', {})

        return jsonify({
            'users': [{'id': 1, 'name': 'John'}, {'id': 2, 'name': 'Jane'}],
            'filters': {
                'id': user_id,
                'name': name
            },
            'monitoring': monitoring.get('analysis', {}) if monitoring else {}
        }), 200

    @app.route('/api/search')
    @monitor_injection(threshold=0.3, block_on_detection=False)  # Custom monitoring
    def search() -> Any:
        """Example search endpoint with custom injection monitoring"""
        query = request.args.get('q', '')
        category = request.args.get('category', '')

        return jsonify({
            'query': query,
            'category': category,
            'results': [
                {'title': 'Result 1', 'url': '/item/1'},
                {'title': 'Result 2', 'url': '/item/2'}
            ]
        }), 200

    @app.route('/admin/config', methods=['POST'])
    @monitor_injection(
        threshold=0.2,  # Very sensitive
        block_on_detection=False,
        custom_response={'error': 'Admin access denied', 'code': 'SECURITY_VIOLATION'}
    )
    def admin_config() -> Any:
        """Example admin endpoint with strict injection monitoring"""
        config_data = request.get_json() or {}

        return jsonify({
            'status': 'updated',
            'config': config_data
        }), 200

    @app.route("/analyze", methods=['POST'])
    def analyze_request() -> Any:
        """Analyze a request for threats without storing it."""
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        source_ip: str = payload.get("source_ip", request.remote_addr or "unknown")
        path: str = payload.get("path", "/")
        method: str = payload.get("method", "GET")
        body: str = payload.get("body", "")
        user_agent: str = payload.get("user_agent", request.headers.get("User-Agent", ""))
        country: str = payload.get("country", "")

        # Log the analysis request
        if STORAGE_AVAILABLE:
            log_info(f"Analyzing request from {source_ip} to {path}", LogType.API, "analyze", {
                'source_ip': source_ip,
                'path': path,
                'method': method,
                'country': country
            })

        # Optional ML anomaly score
        anomaly_score: Optional[float] = None
        if ENHANCED_DETECTORS_AVAILABLE and MLAnomalyDetector:
            try:
                ml = MLAnomalyDetector()
                anomaly_score = ml.predict_anomaly({
                    "source_ip": source_ip,
                    "path": path,
                    "method": method,
                    "body": body,
                    "user_agent": user_agent,
                    "timestamp": request.headers.get("X-Request-Timestamp", ""),
                    "headers": dict(request.headers),
                })
            except Exception:
                anomaly_score = None
        
        # Perform analysis without storing
        is_whitelisted_flag, whitelist_confidence, whitelist_reason = is_whitelisted(source_ip, f"{path} {body}", {
            "user_agent": user_agent,
            "country": country,
            "method": method
        })
        
        # DDoS analysis
        if DDOS_AVAILABLE:
        ddos_record_request(source_ip, path, method, user_agent, country)
        ddos_analysis = analyze_ddos_threat(source_ip)
        else:
            ddos_analysis = {"error": "DDoS detection not available"}
        
        # Injection analysis
        if INJECTION_AVAILABLE:
        path_injection_analysis = analyze_injection_signature(path)
        body_injection_analysis = analyze_injection_signature(body)
        else:
            path_injection_analysis = {"error": "Injection detection not available"}
            body_injection_analysis = {"error": "Injection detection not available"}
        
        result = {
            "whitelisted": is_whitelisted_flag,
            "whitelist_confidence": whitelist_confidence,
            "whitelist_reason": whitelist_reason,
            "ddos_analysis": ddos_analysis,
            "injection_analysis": {
                "path": path_injection_analysis,
                "body": body_injection_analysis
            },
            "anomaly_score": anomaly_score,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Log if threats were detected
        if STORAGE_AVAILABLE:
            if result.get('injection_analysis', {}).get('body', {}).get('has_injection', False):
                log_warning(f"Injection attack detected from {source_ip}", LogType.SECURITY, "analyze", {
                    'source_ip': source_ip,
                    'path': path,
                    'attack_type': result['injection_analysis']['body'].get('attack_type'),
                    'confidence': result['injection_analysis']['body'].get('confidence')
                })

            if result.get('ddos_analysis', {}).get('confidence', 0) > 0.7:
                log_warning(f"High DDoS probability from {source_ip}", LogType.DDoS, "analyze", {
                    'source_ip': source_ip,
                    'confidence': result['ddos_analysis'].get('confidence')
                })

        # Add endpoint monitoring results if available
        monitoring_results = getattr(g, 'injection_monitoring', {})
        if monitoring_results:
            result["endpoint_monitoring"] = monitoring_results.get('analysis', {})

        return jsonify(result), 200

    def process_event(source_ip: str, path: str, method: str, body: str, 
                     user_agent: str = "", country: str = "") -> Dict[str, Any]:
        # Check whitelist first to reduce false positives
        is_whitelisted_flag, whitelist_confidence, whitelist_reason = is_whitelisted(source_ip, f"{path} {body}", {
            "user_agent": user_agent,
            "country": country,
            "method": method
        })
        
        event: Dict[str, Any] = {
            "source_ip": source_ip,
            "path": path,
            "method": method,
            "body": body,
            "user_agent": user_agent,
            "country": country,
            "whitelisted": is_whitelisted_flag,
            "whitelist_confidence": whitelist_confidence,
            "whitelist_reason": whitelist_reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        event_store.add(event)

        # Enhanced DDoS detection with additional metadata
        if DDOS_AVAILABLE:
        ddos_record_request(source_ip, path, method, user_agent, country)
        ddos_flag = is_ddos(source_ip)
            ddos_analysis = analyze_ddos_threat(source_ip)
        else:
            ddos_flag = False
            ddos_analysis = {"confidence": 0.0, "severity": "none"}
        
        # Enhanced injection detection with confidence scoring
        if INJECTION_AVAILABLE:
        path_injection_analysis = analyze_injection_signature(path)
        body_injection_analysis = analyze_injection_signature(body)
        
            injection_flag = (path_injection_analysis.get("has_injection", False) or 
                             body_injection_analysis.get("has_injection", False))
        else:
            path_injection_analysis = {"has_injection": False, "confidence": 0.0}
            body_injection_analysis = {"has_injection": False, "confidence": 0.0}
            injection_flag = False

        # Optional additional rules engine for DDoS/injection
        enhanced_ddos = False
        enhanced_injection = False
        if ENHANCED_DETECTORS_AVAILABLE and DetectionEngine:
            try:
                eng = DetectionEngine()
                enhanced_ddos = bool(eng.detect_ddos({
                    "source_ip": source_ip,
                    "path": path,
                    "method": method,
                    "body": body,
                    "user_agent": user_agent,
                    "headers": {},
                }))
                enhanced_injection = bool(eng.detect_injection({
                    "source_ip": source_ip,
                    "path": path,
                    "method": method,
                    "body": body,
                    "user_agent": user_agent,
                    "headers": {},
                }))
            except Exception:
                enhanced_ddos = False
                enhanced_injection = False

        # Create alerts with enhanced information
        if ddos_flag and not is_whitelisted_flag:
            ddos_alert_store.add({
                    "source_ip": source_ip,
                    "reason": "enhanced_ddos_detection",
                    "path": path,
                    "method": method,
                    "confidence": ddos_analysis.get("confidence", 0.0),
                    "severity": ddos_analysis.get("severity", "medium"),
                    "threats": ddos_analysis.get("threats", []),
                    "recommendations": ddos_analysis.get("recommendations", []),
                "timestamp": datetime.utcnow().isoformat()
            })

        if injection_flag and not is_whitelisted_flag:
            # Use the analysis with higher confidence
            injection_analysis = (path_injection_analysis if 
                                path_injection_analysis.get("confidence", 0.0) > body_injection_analysis.get("confidence", 0.0) 
                                else body_injection_analysis)
            
            injection_alert_store.add({
                    "source_ip": source_ip,
                    "reason": "enhanced_injection_detection",
                    "path": path,
                    "method": method,
                    "confidence": injection_analysis.get("confidence", 0.0),
                    "severity": injection_analysis.get("severity", "medium"),
                    "attack_types": injection_analysis.get("attack_types", []),
                    "details": injection_analysis.get("details", []),
                "timestamp": datetime.utcnow().isoformat()
            })

        # Publish enhanced event data
        publish({
                "type": "event",
                "source_ip": source_ip,
                "path": path,
                "method": method,
                "injection_suspected": injection_flag and not is_whitelisted_flag,
                "ddos_suspected": ddos_flag and not is_whitelisted_flag,
                "whitelisted": is_whitelisted_flag,
                "injection_confidence": max(path_injection_analysis.get("confidence", 0.0),
                                          body_injection_analysis.get("confidence", 0.0)),
                "ddos_confidence": ddos_analysis.get("confidence", 0.0),
                "injection_severity": (path_injection_analysis.get("severity", "none") if 
                                     path_injection_analysis.get("confidence", 0.0) > body_injection_analysis.get("confidence", 0.0)
                                     else body_injection_analysis.get("severity", "none")),
                "ddos_severity": ddos_analysis.get("severity", "none"),
                "enhanced_ddos": enhanced_ddos,
                "enhanced_injection": enhanced_injection,
            "timestamp": datetime.utcnow().isoformat()
        })

        return {
            "stored": True,
            "ddos_suspected": ddos_flag and not is_whitelisted_flag,
            "injection_suspected": injection_flag and not is_whitelisted_flag,
            "whitelisted": is_whitelisted_flag,
            "ddos_analysis": ddos_analysis,
            "injection_analysis": {
                "path": path_injection_analysis,
                "body": body_injection_analysis
            },
            "enhanced_ddos": enhanced_ddos,
            "enhanced_injection": enhanced_injection,
        }

    @app.route("/events", methods=['POST'])
    def create_event() -> Any:
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        source_ip: str = payload.get("source_ip", request.remote_addr or "unknown")
        path: str = payload.get("path", "/")
        method: str = payload.get("method", "GET")
        body: str = payload.get("body", "")
        user_agent: str = payload.get("user_agent", request.headers.get("User-Agent", ""))
        country: str = payload.get("country", "")
        result = process_event(source_ip, path, method, body, user_agent, country)
        return jsonify(result), 201

    # Start sniffer in background if enabled
    def _maybe_start_sniffer() -> None:
        if not SNIFFER_AVAILABLE:
            return

        load_dotenv()
        enabled = os.environ.get("SECUREZZY_SNIFFER_ENABLED", "true").lower() in {"1", "true", "yes"}
        if enabled:
            iface = os.environ.get("SECUREZZY_IFACE") or None
            bpf = os.environ.get("SECUREZZY_BPF", "tcp port 80 or tcp port 443")

            def _cb(event: Dict[str, Any]) -> None:
                try:
                    # Process event for existing detection systems
                    process_event(
                        event.get("source_ip", "unknown"),
                        event.get("path", "/"),
                        event.get("method", "OTHER"),
                        event.get("body", ""),
                        event.get("user_agent", ""),
                        event.get("country", ""),
                    )
                    
                    # Process event for LSTM DDoS detection
                    if LSTM_DDOS_AVAILABLE and analyze_live_ddos:
                        try:
                            # Convert sniffer event to flow format expected by DDoS service
                            flow_data = {
                                'timestamp': event.get('timestamp', time.time()),
                                'src_ip': event.get('source_ip', '0.0.0.0'),
                                'dst_ip': event.get('destination_ip', '0.0.0.0'),
                                'src_port': event.get('source_port', 0),
                                'dst_port': event.get('destination_port', 0),
                                'protocol': event.get('protocol', 'TCP'),
                                'packets_count': event.get('packet_count', 1),
                                'fwd_packets_count': event.get('packet_count', 1),
                                'bwd_packets_count': 0,
                                'duration': event.get('duration', 0.0)
                            }
                            
                            # Analyze with LSTM DDoS service
                            ddos_result = analyze_live_ddos([flow_data], threshold=0.5)
                            
                            # If DDoS attack detected, log it
                            if ddos_result.get('attack_detected', False):
                                print(f"🚨 LSTM DDoS Attack Detected!")
                                print(f"   Probability: {ddos_result.get('max_attack_probability', 0):.3f}")
                                print(f"   Intensity: {ddos_result.get('max_attack_intensity', 0):.3f}")
                                print(f"   Source IP: {flow_data['src_ip']}")
                                
                                # Store DDoS alert
                                if STORAGE_AVAILABLE:
                                    try:
                                        event_store.store_event({
                                            'type': 'ddos_attack',
                                            'source_ip': flow_data['src_ip'],
                                            'attack_probability': ddos_result.get('max_attack_probability', 0),
                                            'attack_intensity': ddos_result.get('max_attack_intensity', 0),
                                            'confidence': ddos_result.get('confidence', 0),
                                            'timestamp': time.time(),
                                            'details': ddos_result
                                        })
                                    except Exception as e:
                                        print(f"Failed to store DDoS alert: {e}")
                                        
                        except Exception as e:
                            print(f"DDoS analysis error: {e}")
                            
                except Exception:
                    pass

            t = threading.Thread(target=run_sniffer, kwargs={
                "callback": _cb,
                "iface": iface,
                "bpf_filter": bpf,
                "timeout": None,
                "count": 0,
            }, daemon=True)
            t.start()
            print(f"✅ Network sniffer started on interface: {iface}")

    # Catch-all route for frontend files (must be last)
    @app.route("/<path:filename>")
    def frontend_files(filename) -> Any:
        return send_from_directory('../frontend', filename)

    _maybe_start_sniffer()

    return app


app = create_app()

if __name__ == "__main__":
    print("🚀 Starting Enhanced Security Monitoring System")
    print("=" * 60)
    print("Services Status:")
    print(f"  Storage: {'✅' if STORAGE_AVAILABLE else '❌'}")
    print(f"  DDoS Detection: {'✅' if DDOS_AVAILABLE else '❌'}")
    print(f"  LSTM DDoS Service: {'✅' if LSTM_DDOS_AVAILABLE else '❌'}")
    print(f"  Injection Detection: {'✅' if INJECTION_AVAILABLE else '❌'}")
    print(f"  Whitelist: {'✅' if WHITELIST_AVAILABLE else '❌'}")
    print(f"  Sniffer: {'✅' if SNIFFER_AVAILABLE else '❌'}")
    print(f"  Production Injection Service: {'✅' if INJECTION_SERVICE_AVAILABLE else '❌'}")
    print(f"  Enhanced Detectors: {'✅' if ENHANCED_DETECTORS_AVAILABLE else '❌'}")
    
    # Log system startup
    if STORAGE_AVAILABLE:
        log_info("Enhanced Security Monitoring System started", LogType.SYSTEM, "startup", {
            'services': {
                'storage': STORAGE_AVAILABLE,
                'ddos': DDOS_AVAILABLE,
                'lstm_ddos': LSTM_DDOS_AVAILABLE,
                'injection': INJECTION_AVAILABLE,
                'whitelist': WHITELIST_AVAILABLE,
                'sniffer': SNIFFER_AVAILABLE,
                'production_injection': INJECTION_SERVICE_AVAILABLE,
                'enhanced_detectors': ENHANCED_DETECTORS_AVAILABLE
            }
        })
    print()
    print("Available Endpoints:")
    print("  GET  /health - System health check")
    print("  GET  /events - List events")
    print("  POST /events - Create event")
    print("  GET  /alerts/ddos - DDoS alerts")
    print("  GET  /alerts/injection - Injection alerts")
    print("  POST /analyze - Analyze request")
    print("  GET  /monitor/stats - Monitoring statistics")
    print("  GET  /monitor/alerts - Monitoring alerts")
    print("  GET  /sniffer/status - Sniffer status")
    print("  POST /sniffer/config - Configure sniffer")
    print("  GET  /sniffer/interfaces - Available interfaces")
    print("  GET  /ddos/lstm/status - LSTM DDoS service status")
    print("  POST /ddos/lstm/analyze - Analyze traffic with LSTM")
    print("  GET  /ddos/lstm/alerts - Get recent DDoS alerts")
    print("  GET  /logs - Get logs with filtering")
    print("  GET  /logs/statistics - Get log statistics")
    print("  POST /logs/clear - Clear all logs")
    print("  GET  /logs/export - Export logs as JSON")
    # LSTM DDoS integration complete
    print("  GET  /api/users - Example monitored endpoint")
    print("  GET  /api/search - Example search endpoint")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)
