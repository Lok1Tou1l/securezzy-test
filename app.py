from flask import Flask, jsonify, request
from flask import make_response
import json
from queue import Queue, Empty
from typing import List
from typing import Any, Dict, Optional

from storage import (
    event_store,
    ddos_alert_store,
    injection_alert_store,
)
from detection.ddos import record_request as ddos_record_request, is_ddos, analyze_ddos_threat
from detection.injection import has_injection_signature, analyze_injection_signature
from detection.whitelist import is_whitelisted, whitelist_manager
from sniffer import run_sniffer

# Optional enhanced detectors (graceful fallback if deps not installed)
try:
    from new.detection_engine import DetectionEngine  # type: ignore
    from new.ml_detector import MLAnomalyDetector  # type: ignore
except Exception:
    DetectionEngine = None  # type: ignore
    MLAnomalyDetector = None  # type: ignore
import threading
import os
from dotenv import load_dotenv


def create_app() -> Flask:
    app = Flask(__name__)

    # Simple in-process pub/sub for Server-Sent Events (SSE)
    subscribers: List[Queue] = []

    def publish(event_dict: Dict[str, Any]) -> None:
        for q in list(subscribers):
            try:
                q.put_nowait(event_dict)
            except Exception:
                # Best effort; drop if queue is closed
                pass

    @app.get("/stream/events")
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

    @app.get("/health")
    def health() -> Any:
        return jsonify({"status": "ok"}), 200

    @app.get("/events")
    def list_events() -> Any:
        return jsonify(event_store.get_all()), 200

    @app.get("/alerts/ddos")
    def list_ddos_alerts() -> Any:
        return jsonify(ddos_alert_store.get_all()), 200

    @app.get("/alerts/injection")
    def list_injection_alerts() -> Any:
        return jsonify(injection_alert_store.get_all()), 200

    @app.get("/whitelist")
    def get_whitelist() -> Any:
        """Get whitelist statistics and entries."""
        return jsonify(whitelist_manager.get_statistics()), 200

    @app.post("/whitelist/ip")
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

    @app.post("/whitelist/pattern")
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

    @app.delete("/whitelist/<value>")
    def remove_whitelist_entry(value: str) -> Any:
        """Remove whitelist entry."""
        success = whitelist_manager.remove_whitelist(value)
        if success:
            return jsonify({"message": f"Whitelist entry {value} removed"}), 200
        else:
            return jsonify({"error": "Whitelist entry not found"}), 404

    @app.get("/analytics/injection")
    def get_injection_analytics() -> Any:
        """Get injection detection analytics."""
        from detection.injection import get_injection_statistics
        return jsonify(get_injection_statistics()), 200

    @app.get("/analytics/ddos")
    def get_ddos_analytics() -> Any:
        """Get DDoS detection analytics."""
        from detection.ddos import get_ddos_statistics
        return jsonify(get_ddos_statistics()), 200

    @app.post("/analyze")
    def analyze_request() -> Any:
        """Analyze a request for threats without storing it."""
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        source_ip: str = payload.get("source_ip", request.remote_addr or "unknown")
        path: str = payload.get("path", "/")
        method: str = payload.get("method", "GET")
        body: str = payload.get("body", "")
        user_agent: str = payload.get("user_agent", request.headers.get("User-Agent", ""))
        country: str = payload.get("country", "")

        # Optional ML anomaly score
        anomaly_score: Optional[float] = None
        if MLAnomalyDetector:
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
        whitelist_result = is_whitelisted(source_ip, f"{path} {body}", {
            "user_agent": user_agent,
            "country": country,
            "method": method
        })
        
        is_whitelisted_flag, whitelist_confidence, whitelist_reason = whitelist_result
        
        # DDoS analysis
        ddos_record_request(source_ip, path, method, user_agent, country)
        ddos_analysis = analyze_ddos_threat(source_ip)
        
        # Injection analysis
        path_injection_analysis = analyze_injection_signature(path)
        body_injection_analysis = analyze_injection_signature(body)
        
        return jsonify({
            "whitelisted": is_whitelisted_flag,
            "whitelist_confidence": whitelist_confidence,
            "whitelist_reason": whitelist_reason,
            "ddos_analysis": ddos_analysis,
            "injection_analysis": {
                "path": path_injection_analysis,
                "body": body_injection_analysis
            },
            "anomaly_score": anomaly_score
        }), 200

    def process_event(source_ip: str, path: str, method: str, body: str, 
                     user_agent: str = "", country: str = "") -> Dict[str, Any]:
        # Check whitelist first to reduce false positives
        whitelist_result = is_whitelisted(source_ip, f"{path} {body}", {
            "user_agent": user_agent,
            "country": country,
            "method": method
        })
        
        is_whitelisted_flag, whitelist_confidence, whitelist_reason = whitelist_result
        
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
        }
        event_store.add(event)

        # Enhanced DDoS detection with additional metadata
        ddos_record_request(source_ip, path, method, user_agent, country)
        ddos_flag = is_ddos(source_ip)
        
        # Enhanced injection detection with confidence scoring
        path_injection_analysis = analyze_injection_signature(path)
        body_injection_analysis = analyze_injection_signature(body)
        
        injection_flag = (path_injection_analysis["has_injection"] or 
                         body_injection_analysis["has_injection"])
        
        # Get detailed DDoS analysis
        ddos_analysis = analyze_ddos_threat(source_ip)
        
        # Optional additional rules engine for DDoS/injection from new.detection_engine
        enhanced_ddos = False
        enhanced_injection = False
        if DetectionEngine:
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
            ddos_alert_store.add(
                {
                    "source_ip": source_ip,
                    "reason": "enhanced_ddos_detection",
                    "path": path,
                    "method": method,
                    "confidence": ddos_analysis.get("confidence", 0.0),
                    "severity": ddos_analysis.get("severity", "medium"),
                    "threats": ddos_analysis.get("threats", []),
                    "recommendations": ddos_analysis.get("recommendations", []),
                }
            )

        if injection_flag and not is_whitelisted_flag:
            # Use the analysis with higher confidence
            injection_analysis = (path_injection_analysis if 
                                path_injection_analysis["confidence"] > body_injection_analysis["confidence"] 
                                else body_injection_analysis)
            
            injection_alert_store.add(
                {
                    "source_ip": source_ip,
                    "reason": "enhanced_injection_detection",
                    "path": path,
                    "method": method,
                    "confidence": injection_analysis.get("confidence", 0.0),
                    "severity": injection_analysis.get("severity", "medium"),
                    "attack_types": injection_analysis.get("attack_types", []),
                    "details": injection_analysis.get("details", []),
                }
            )

        # Publish enhanced event data
        publish(
            {
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
            }
        )

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

    @app.post("/events")
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
        load_dotenv()
        enabled = os.environ.get("SECUREZZY_SNIFFER_ENABLED", "true").lower() in {"1", "true", "yes"}
        if enabled:
            iface = os.environ.get("SECUREZZY_IFACE") or None
            bpf = os.environ.get("SECUREZZY_BPF", "tcp port 80 or tcp port 443")

            def _cb(event: Dict[str, Any]) -> None:
                try:
                    process_event(
                        event.get("source_ip", "unknown"),
                        event.get("path", "/"),
                        event.get("method", "OTHER"),
                        event.get("body", ""),
                        event.get("user_agent", ""),
                        event.get("country", ""),
                    )
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

    _maybe_start_sniffer()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


