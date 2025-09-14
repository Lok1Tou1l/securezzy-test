from flask import Flask, jsonify, request
from flask import make_response
import json
from queue import Queue, Empty
from typing import List
from typing import Any, Dict

from storage import (
    event_store,
    ddos_alert_store,
    injection_alert_store,
)
from detection.ddos import record_request as ddos_record_request, is_ddos
from detection.injection import has_injection_signature
from sniffer import run_sniffer
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

    def process_event(source_ip: str, path: str, method: str, body: str) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "source_ip": source_ip,
            "path": path,
            "method": method,
            "body": body,
        }
        event_store.add(event)

        ddos_record_request(source_ip)
        ddos_flag = is_ddos(source_ip)
        injection_flag = has_injection_signature(path) or has_injection_signature(body)

        if ddos_flag:
            ddos_alert_store.add(
                {
                    "source_ip": source_ip,
                    "reason": "threshold_exceeded",
                    "path": path,
                    "method": method,
                }
            )

        if injection_flag:
            injection_alert_store.add(
                {
                    "source_ip": source_ip,
                    "reason": "injection_signature",
                    "path": path,
                    "method": method,
                }
            )

        publish(
            {
                "type": "event",
                "source_ip": source_ip,
                "path": path,
                "method": method,
                "injection_suspected": injection_flag,
                "ddos_suspected": ddos_flag,
            }
        )

        return {
            "stored": True,
            "ddos_suspected": ddos_flag,
            "injection_suspected": injection_flag,
        }

    @app.post("/events")
    def create_event() -> Any:
        payload: Dict[str, Any] = request.get_json(silent=True) or {}
        source_ip: str = payload.get("source_ip", request.remote_addr or "unknown")
        path: str = payload.get("path", "/")
        method: str = payload.get("method", "GET")
        body: str = payload.get("body", "")
        result = process_event(source_ip, path, method, body)
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


