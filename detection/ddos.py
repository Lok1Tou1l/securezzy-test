import time
import hashlib
import json
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum


class DDoSType(Enum):
    VOLUME = "volume"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    BEHAVIORAL = "behavioral"


@dataclass
class DDoSAlert:
    source_ip: str
    ddos_type: DDoSType
    confidence: float
    severity: str
    details: Dict[str, Any]
    timestamp: float


# Configuration parameters
REQUEST_WINDOW_SECONDS = 10
REQUEST_THRESHOLD = 20
BURST_THRESHOLD = 50  # Requests in 1 second
SUSTAINED_THRESHOLD = 100  # Requests in 60 seconds
BEHAVIORAL_WINDOW = 300  # 5 minutes for behavioral analysis
GEOGRAPHIC_CLUSTER_THRESHOLD = 10  # IPs from same country
USER_AGENT_ANOMALY_THRESHOLD = 0.8  # 80% same user agent

# Rate limiting configuration
RATE_LIMIT_WINDOWS = {
    "1s": 1,
    "10s": 10,
    "60s": 60,
    "300s": 300
}

RATE_LIMIT_THRESHOLDS = {
    "1s": 20,
    "10s": 100,
    "60s": 500,
    "300s": 1000
}


# Global state
_ip_to_timestamps: Dict[str, Deque[float]] = defaultdict(deque)
_ip_to_requests: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
_ip_to_user_agents: Dict[str, List[str]] = defaultdict(list)
_ip_to_paths: Dict[str, List[str]] = defaultdict(list)
_geographic_clusters: Dict[str, List[str]] = defaultdict(list)
_behavioral_baselines: Dict[str, Dict[str, Any]] = defaultdict(dict)
_ddos_alerts: List[DDoSAlert] = []


def record_request(source_ip: str, path: str = "/", method: str = "GET", 
                  user_agent: str = "", country: str = "") -> None:
    """
    Record a request with enhanced metadata for advanced DDoS detection.
    
    Args:
        source_ip: Source IP address
        path: Request path
        method: HTTP method
        user_agent: User agent string
        country: Country code (if available)
    """
    now = time.time()
    
    # Basic timestamp tracking
    timestamps = _ip_to_timestamps[source_ip]
    timestamps.append(now)
    _evict_old_timestamps(timestamps, now)
    
    # Enhanced request tracking
    request_data = {
        "timestamp": now,
        "path": path,
        "method": method,
        "user_agent": user_agent,
        "country": country
    }
    
    requests = _ip_to_requests[source_ip]
    requests.append(request_data)
    _evict_old_requests(requests, now)
    
    # Track user agents for behavioral analysis
    if user_agent:
        user_agents = _ip_to_user_agents[source_ip]
        user_agents.append(user_agent)
        if len(user_agents) > 100:  # Keep last 100 user agents
            user_agents.pop(0)
    
    # Track paths for behavioral analysis
    paths = _ip_to_paths[source_ip]
    paths.append(path)
    if len(paths) > 100:  # Keep last 100 paths
        paths.pop(0)
    
    # Geographic clustering
    if country:
        _geographic_clusters[country].append(source_ip)
        if len(_geographic_clusters[country]) > 1000:  # Limit cluster size
            _geographic_clusters[country].pop(0)


def is_ddos(source_ip: str) -> bool:
    """
    Enhanced DDoS detection with multiple algorithms.
    
    Returns:
        bool: True if DDoS attack detected
    """
    now = time.time()
    
    # Check all DDoS types
    volume_ddos = _detect_volume_ddos(source_ip, now)
    behavioral_ddos = _detect_behavioral_ddos(source_ip, now)
    geographic_ddos = _detect_geographic_ddos(source_ip, now)
    protocol_ddos = _detect_protocol_ddos(source_ip, now)
    
    # Return True if any detection method triggers
    return any([volume_ddos, behavioral_ddos, geographic_ddos, protocol_ddos])


def analyze_ddos_threat(source_ip: str) -> Dict[str, Any]:
    """
    Comprehensive DDoS threat analysis.
    
    Returns:
        Dict containing detailed analysis results
    """
    now = time.time()
    
    analysis = {
        "source_ip": source_ip,
        "timestamp": now,
        "threats": [],
        "confidence": 0.0,
        "severity": "none",
        "recommendations": []
    }
    
    # Volume-based analysis
    volume_analysis = _analyze_volume_patterns(source_ip, now)
    if volume_analysis["is_threat"]:
        analysis["threats"].append(volume_analysis)
    
    # Behavioral analysis
    behavioral_analysis = _analyze_behavioral_patterns(source_ip, now)
    if behavioral_analysis["is_threat"]:
        analysis["threats"].append(behavioral_analysis)
    
    # Geographic analysis
    geographic_analysis = _analyze_geographic_patterns(source_ip, now)
    if geographic_analysis["is_threat"]:
        analysis["threats"].append(geographic_analysis)
    
    # Protocol analysis
    protocol_analysis = _analyze_protocol_patterns(source_ip, now)
    if protocol_analysis["is_threat"]:
        analysis["threats"].append(protocol_analysis)
    
    # Calculate overall confidence and severity
    if analysis["threats"]:
        max_confidence = max(threat["confidence"] for threat in analysis["threats"])
        analysis["confidence"] = max_confidence
        analysis["severity"] = _determine_ddos_severity(max_confidence)
        analysis["recommendations"] = _generate_ddos_recommendations(analysis["threats"])
    
    return analysis


def _detect_volume_ddos(source_ip: str, now: float) -> bool:
    """Detect volume-based DDoS attacks."""
    timestamps = _ip_to_timestamps[source_ip]
    _evict_old_timestamps(timestamps, now)
    
    # Check multiple time windows
    for window_name, window_seconds in RATE_LIMIT_WINDOWS.items():
        threshold = RATE_LIMIT_THRESHOLDS[window_name]
        window_timestamps = [ts for ts in timestamps if now - ts <= window_seconds]
        
        if len(window_timestamps) > threshold:
            return True
    
    return False


def _detect_behavioral_ddos(source_ip: str, now: float) -> bool:
    """Detect behavioral anomalies that might indicate DDoS."""
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= BEHAVIORAL_WINDOW]
    
    if len(recent_requests) < 10:  # Need minimum data for analysis
        return False
    
    # Check for repetitive patterns
    paths = [req["path"] for req in recent_requests]
    user_agents = [req["user_agent"] for req in recent_requests if req["user_agent"]]
    
    # High repetition of same path
    if paths:
        most_common_path = max(set(paths), key=paths.count)
        path_repetition = paths.count(most_common_path) / len(paths)
        if path_repetition > 0.9:  # 90% same path
            return True
    
    # High repetition of same user agent
    if user_agents:
        most_common_ua = max(set(user_agents), key=user_agents.count)
        ua_repetition = user_agents.count(most_common_ua) / len(user_agents)
        if ua_repetition > USER_AGENT_ANOMALY_THRESHOLD:
            return True
    
    return False


def _detect_geographic_ddos(source_ip: str, now: float) -> bool:
    """Detect geographic clustering attacks."""
    # This would require IP geolocation service
    # For now, we'll implement a simple version
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= 60]
    
    if len(recent_requests) < 5:
        return False
    
    # Check if requests come from same country (if available)
    countries = [req["country"] for req in recent_requests if req["country"]]
    if countries:
        most_common_country = max(set(countries), key=countries.count)
        country_repetition = countries.count(most_common_country) / len(countries)
        if country_repetition > 0.8:  # 80% from same country
            return True
    
    return False


def _detect_protocol_ddos(source_ip: str, now: float) -> bool:
    """Detect protocol-level DDoS attacks."""
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= 60]
    
    if len(recent_requests) < 10:
        return False
    
    # Check for unusual HTTP methods
    methods = [req["method"] for req in recent_requests]
    unusual_methods = ["TRACE", "OPTIONS", "HEAD"]
    unusual_count = sum(1 for method in methods if method in unusual_methods)
    
    if unusual_count / len(methods) > 0.3:  # 30% unusual methods
        return True
    
    return False


def _analyze_volume_patterns(source_ip: str, now: float) -> Dict[str, Any]:
    """Analyze volume-based attack patterns."""
    timestamps = _ip_to_timestamps[source_ip]
    _evict_old_timestamps(timestamps, now)
    
    analysis = {
        "type": "volume",
        "is_threat": False,
        "confidence": 0.0,
        "details": {},
        "metrics": {}
    }
    
    for window_name, window_seconds in RATE_LIMIT_WINDOWS.items():
        threshold = RATE_LIMIT_THRESHOLDS[window_name]
        window_timestamps = [ts for ts in timestamps if now - ts <= window_seconds]
        request_count = len(window_timestamps)
        
        analysis["metrics"][window_name] = {
            "requests": request_count,
            "threshold": threshold,
            "exceeded": request_count > threshold
        }
        
        if request_count > threshold:
            analysis["is_threat"] = True
            confidence = min(1.0, request_count / threshold)
            analysis["confidence"] = max(analysis["confidence"], confidence)
    
    return analysis


def _analyze_behavioral_patterns(source_ip: str, now: float) -> Dict[str, Any]:
    """Analyze behavioral attack patterns."""
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= BEHAVIORAL_WINDOW]
    
    analysis = {
        "type": "behavioral",
        "is_threat": False,
        "confidence": 0.0,
        "details": {},
        "metrics": {}
    }
    
    if len(recent_requests) < 10:
        return analysis
    
    # Analyze path patterns
    paths = [req["path"] for req in recent_requests]
    unique_paths = len(set(paths))
    total_requests = len(paths)
    
    analysis["metrics"]["path_diversity"] = {
        "unique_paths": unique_paths,
        "total_requests": total_requests,
        "diversity_ratio": unique_paths / total_requests
    }
    
    # Check for repetitive behavior
    if unique_paths / total_requests < 0.1:  # Less than 10% path diversity
        analysis["is_threat"] = True
        analysis["confidence"] = 0.8
        analysis["details"]["repetitive_paths"] = True
    
    # Analyze user agent patterns
    user_agents = [req["user_agent"] for req in recent_requests if req["user_agent"]]
    if user_agents:
        unique_uas = len(set(user_agents))
        ua_diversity = unique_uas / len(user_agents)
        
        analysis["metrics"]["user_agent_diversity"] = {
            "unique_user_agents": unique_uas,
            "total_user_agents": len(user_agents),
            "diversity_ratio": ua_diversity
        }
        
        if ua_diversity < 0.2:  # Less than 20% user agent diversity
            analysis["is_threat"] = True
            analysis["confidence"] = max(analysis["confidence"], 0.7)
            analysis["details"]["repetitive_user_agents"] = True
    
    return analysis


def _analyze_geographic_patterns(source_ip: str, now: float) -> Dict[str, Any]:
    """Analyze geographic attack patterns."""
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= 60]
    
    analysis = {
        "type": "geographic",
        "is_threat": False,
        "confidence": 0.0,
        "details": {},
        "metrics": {}
    }
    
    if len(recent_requests) < 5:
        return analysis
    
    countries = [req["country"] for req in recent_requests if req["country"]]
    if countries:
        unique_countries = len(set(countries))
        country_diversity = unique_countries / len(countries)
        
        analysis["metrics"]["geographic_diversity"] = {
            "unique_countries": unique_countries,
            "total_requests": len(countries),
            "diversity_ratio": country_diversity
        }
        
        if country_diversity < 0.3:  # Less than 30% country diversity
            analysis["is_threat"] = True
            analysis["confidence"] = 0.6
            analysis["details"]["geographic_clustering"] = True
    
    return analysis


def _analyze_protocol_patterns(source_ip: str, now: float) -> Dict[str, Any]:
    """Analyze protocol-level attack patterns."""
    requests = _ip_to_requests[source_ip]
    recent_requests = [req for req in requests if now - req["timestamp"] <= 60]
    
    analysis = {
        "type": "protocol",
        "is_threat": False,
        "confidence": 0.0,
        "details": {},
        "metrics": {}
    }
    
    if len(recent_requests) < 10:
        return analysis
    
    methods = [req["method"] for req in recent_requests]
    method_counts = {}
    for method in methods:
        method_counts[method] = method_counts.get(method, 0) + 1
    
    analysis["metrics"]["method_distribution"] = method_counts
    
    # Check for unusual method patterns
    unusual_methods = ["TRACE", "OPTIONS", "HEAD"]
    unusual_count = sum(method_counts.get(method, 0) for method in unusual_methods)
    unusual_ratio = unusual_count / len(methods)
    
    if unusual_ratio > 0.3:  # More than 30% unusual methods
        analysis["is_threat"] = True
        analysis["confidence"] = 0.7
        analysis["details"]["unusual_methods"] = True
    
    return analysis


def _determine_ddos_severity(confidence: float) -> str:
    """Determine DDoS severity based on confidence score."""
    if confidence >= 0.9:
        return "critical"
    elif confidence >= 0.7:
        return "high"
    elif confidence >= 0.5:
        return "medium"
    elif confidence >= 0.3:
        return "low"
    else:
        return "none"


def _generate_ddos_recommendations(threats: List[Dict[str, Any]]) -> List[str]:
    """Generate recommendations based on detected threats."""
    recommendations = []
    
    for threat in threats:
        if threat["type"] == "volume":
            recommendations.append("Implement rate limiting and request throttling")
            recommendations.append("Consider using a CDN or DDoS protection service")
        elif threat["type"] == "behavioral":
            recommendations.append("Implement behavioral analysis and anomaly detection")
            recommendations.append("Add CAPTCHA or challenge-response mechanisms")
        elif threat["type"] == "geographic":
            recommendations.append("Implement geographic filtering and blocking")
            recommendations.append("Monitor for coordinated attacks from specific regions")
        elif threat["type"] == "protocol":
            recommendations.append("Implement protocol-level filtering")
            recommendations.append("Block or limit unusual HTTP methods")
    
    return list(set(recommendations))  # Remove duplicates


def _evict_old_timestamps(timestamps: Deque[float], now: float) -> None:
    """Remove old timestamps outside the analysis window."""
    threshold = now - max(RATE_LIMIT_WINDOWS.values())
    while timestamps and timestamps[0] < threshold:
        timestamps.popleft()


def _evict_old_requests(requests: List[Dict[str, Any]], now: float) -> None:
    """Remove old requests outside the analysis window."""
    threshold = now - BEHAVIORAL_WINDOW
    while requests and requests[0]["timestamp"] < threshold:
        requests.pop(0)


def get_ddos_statistics() -> Dict[str, Any]:
    """Get statistics about DDoS detection system."""
    now = time.time()
    
    # Count active IPs
    active_ips = 0
    for ip, timestamps in _ip_to_timestamps.items():
        _evict_old_timestamps(timestamps, now)
        if timestamps:
            active_ips += 1
    
    # Count recent alerts
    recent_alerts = len([alert for alert in _ddos_alerts if now - alert.timestamp <= 3600])
    
    return {
        "active_ips": active_ips,
        "total_alerts": len(_ddos_alerts),
        "recent_alerts": recent_alerts,
        "rate_limit_windows": len(RATE_LIMIT_WINDOWS),
        "behavioral_window_seconds": BEHAVIORAL_WINDOW,
        "geographic_clusters": len(_geographic_clusters)
    }


