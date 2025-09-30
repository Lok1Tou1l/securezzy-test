"""
Advanced whitelisting and false positive reduction system.

This module provides comprehensive whitelisting capabilities to reduce false positives
in security detection, including IP whitelisting, pattern whitelisting, and behavioral
whitelisting based on historical data.
"""

import time
import hashlib
import json
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re


class WhitelistType(Enum):
    IP = "ip"
    PATTERN = "pattern"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    GEOGRAPHIC = "geographic"


@dataclass
class WhitelistEntry:
    entry_type: WhitelistType
    value: str
    confidence: float
    reason: str
    created_at: float
    expires_at: Optional[float] = None
    usage_count: int = 0
    last_used: Optional[float] = None


class WhitelistManager:
    """Manages whitelist entries and provides false positive reduction."""
    
    def __init__(self):
        self._entries: Dict[str, WhitelistEntry] = {}
        self._ip_ranges: List[Tuple[ipaddress.IPv4Network, WhitelistEntry]] = []
        self._pattern_cache: Dict[str, re.Pattern] = {}
        self._behavioral_baselines: Dict[str, Dict[str, Any]] = {}
        self._temporal_patterns: Dict[str, List[Tuple[int, int]]] = {}  # hour, minute patterns
        
    def add_ip_whitelist(self, ip: str, reason: str = "Manual whitelist", 
                        confidence: float = 1.0, expires_at: Optional[float] = None) -> bool:
        """Add an IP address or IP range to the whitelist."""
        try:
            # Handle IP ranges
            if '/' in ip:
                network = ipaddress.IPv4Network(ip, strict=False)
                entry = WhitelistEntry(
                    entry_type=WhitelistType.IP,
                    value=ip,
                    confidence=confidence,
                    reason=reason,
                    created_at=time.time(),
                    expires_at=expires_at
                )
                self._ip_ranges.append((network, entry))
                self._entries[ip] = entry
                return True
            else:
                # Single IP
                ipaddress.IPv4Address(ip)  # Validate IP
                entry = WhitelistEntry(
                    entry_type=WhitelistType.IP,
                    value=ip,
                    confidence=confidence,
                    reason=reason,
                    created_at=time.time(),
                    expires_at=expires_at
                )
                self._entries[ip] = entry
                return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def add_pattern_whitelist(self, pattern: str, reason: str = "Manual pattern whitelist",
                             confidence: float = 1.0, expires_at: Optional[float] = None) -> bool:
        """Add a regex pattern to the whitelist."""
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self._pattern_cache[pattern] = compiled_pattern
            
            entry = WhitelistEntry(
                entry_type=WhitelistType.PATTERN,
                value=pattern,
                confidence=confidence,
                reason=reason,
                created_at=time.time(),
                expires_at=expires_at
            )
            self._entries[pattern] = entry
            return True
        except re.error:
            return False
    
    def add_behavioral_whitelist(self, ip: str, behavior_type: str, 
                                baseline_data: Dict[str, Any], reason: str = "Behavioral baseline") -> bool:
        """Add behavioral whitelist based on historical patterns."""
        entry_key = f"{ip}:{behavior_type}"
        
        entry = WhitelistEntry(
            entry_type=WhitelistType.BEHAVIORAL,
            value=entry_key,
            confidence=0.8,  # Behavioral whitelists have moderate confidence
            reason=reason,
            created_at=time.time()
        )
        
        self._entries[entry_key] = entry
        self._behavioral_baselines[entry_key] = baseline_data
        return True
    
    def add_temporal_whitelist(self, ip: str, hour: int, minute: int, 
                              duration_minutes: int = 60, reason: str = "Temporal pattern") -> bool:
        """Add temporal whitelist for specific time patterns."""
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            return False
        
        entry_key = f"{ip}:temporal"
        
        if entry_key not in self._temporal_patterns:
            self._temporal_patterns[entry_key] = []
        
        self._temporal_patterns[entry_key].append((hour, minute))
        
        entry = WhitelistEntry(
            entry_type=WhitelistType.TEMPORAL,
            value=entry_key,
            confidence=0.7,  # Temporal patterns have moderate confidence
            reason=reason,
            created_at=time.time()
        )
        
        self._entries[entry_key] = entry
        return True
    
    def is_whitelisted(self, ip: str, text: str = "", context: Dict[str, Any] = None) -> Tuple[bool, float, str]:
        """
        Check if an IP or text is whitelisted.
        
        Returns:
            Tuple of (is_whitelisted, confidence, reason)
        """
        if context is None:
            context = {}
        
        # Check IP whitelist
        ip_result = self._check_ip_whitelist(ip)
        if ip_result[0]:
            return ip_result
        
        # Check pattern whitelist
        if text:
            pattern_result = self._check_pattern_whitelist(text)
            if pattern_result[0]:
                return pattern_result
        
        # Check behavioral whitelist
        behavioral_result = self._check_behavioral_whitelist(ip, context)
        if behavioral_result[0]:
            return behavioral_result
        
        # Check temporal whitelist
        temporal_result = self._check_temporal_whitelist(ip)
        if temporal_result[0]:
            return temporal_result
        
        return False, 0.0, ""
    
    def _check_ip_whitelist(self, ip: str) -> Tuple[bool, float, str]:
        """Check if IP is in whitelist."""
        # Check exact IP match
        if ip in self._entries:
            entry = self._entries[ip]
            if self._is_entry_valid(entry):
                entry.usage_count += 1
                entry.last_used = time.time()
                return True, entry.confidence, entry.reason
        
        # Check IP ranges
        try:
            ip_addr = ipaddress.IPv4Address(ip)
            for network, entry in self._ip_ranges:
                if self._is_entry_valid(entry) and ip_addr in network:
                    entry.usage_count += 1
                    entry.last_used = time.time()
                    return True, entry.confidence, entry.reason
        except ipaddress.AddressValueError:
            pass
        
        return False, 0.0, ""
    
    def _check_pattern_whitelist(self, text: str) -> Tuple[bool, float, str]:
        """Check if text matches whitelist patterns."""
        for pattern_str, entry in self._entries.items():
            if (entry.entry_type == WhitelistType.PATTERN and 
                self._is_entry_valid(entry)):
                
                compiled_pattern = self._pattern_cache.get(pattern_str)
                if compiled_pattern and compiled_pattern.search(text):
                    entry.usage_count += 1
                    entry.last_used = time.time()
                    return True, entry.confidence, entry.reason
        
        return False, 0.0, ""
    
    def _check_behavioral_whitelist(self, ip: str, context: Dict[str, Any]) -> Tuple[bool, float, str]:
        """Check behavioral whitelist based on context."""
        for entry_key, entry in self._entries.items():
            if (entry.entry_type == WhitelistType.BEHAVIORAL and 
                self._is_entry_valid(entry) and 
                entry_key.startswith(f"{ip}:")):
                
                baseline = self._behavioral_baselines.get(entry_key)
                if baseline and self._matches_behavioral_baseline(context, baseline):
                    entry.usage_count += 1
                    entry.last_used = time.time()
                    return True, entry.confidence, entry.reason
        
        return False, 0.0, ""
    
    def _check_temporal_whitelist(self, ip: str) -> Tuple[bool, float, str]:
        """Check temporal whitelist based on current time."""
        now = time.localtime()
        current_hour = now.tm_hour
        current_minute = now.tm_min
        
        entry_key = f"{ip}:temporal"
        if entry_key in self._temporal_patterns:
            patterns = self._temporal_patterns[entry_key]
            for hour, minute in patterns:
                # Check if current time is within the temporal pattern
                if (current_hour == hour and 
                    abs(current_minute - minute) <= 30):  # 30-minute window
                    entry = self._entries.get(entry_key)
                    if entry and self._is_entry_valid(entry):
                        entry.usage_count += 1
                        entry.last_used = time.time()
                        return True, entry.confidence, entry.reason
        
        return False, 0.0, ""
    
    def _is_entry_valid(self, entry: WhitelistEntry) -> bool:
        """Check if whitelist entry is still valid."""
        if entry.expires_at and time.time() > entry.expires_at:
            return False
        return True
    
    def _matches_behavioral_baseline(self, context: Dict[str, Any], baseline: Dict[str, Any]) -> bool:
        """Check if current context matches behavioral baseline."""
        # Simple behavioral matching - can be enhanced
        for key, expected_value in baseline.items():
            if key in context:
                if isinstance(expected_value, (int, float)):
                    # Numeric comparison with tolerance
                    if abs(context[key] - expected_value) > expected_value * 0.2:  # 20% tolerance
                        return False
                else:
                    # String comparison
                    if context[key] != expected_value:
                        return False
            else:
                return False
        return True
    
    def remove_whitelist(self, value: str) -> bool:
        """Remove a whitelist entry."""
        if value in self._entries:
            entry = self._entries[value]
            del self._entries[value]
            
            # Remove from IP ranges if applicable
            if entry.entry_type == WhitelistType.IP and '/' in value:
                self._ip_ranges = [(net, ent) for net, ent in self._ip_ranges if ent != entry]
            
            # Remove from pattern cache
            if entry.entry_type == WhitelistType.PATTERN and value in self._pattern_cache:
                del self._pattern_cache[value]
            
            # Remove from behavioral baselines
            if entry.entry_type == WhitelistType.BEHAVIORAL and value in self._behavioral_baselines:
                del self._behavioral_baselines[value]
            
            # Remove from temporal patterns
            if entry.entry_type == WhitelistType.TEMPORAL and value in self._temporal_patterns:
                del self._temporal_patterns[value]
            
            return True
        return False
    
    def cleanup_expired(self) -> int:
        """Remove expired whitelist entries."""
        now = time.time()
        expired_keys = []
        
        for key, entry in self._entries.items():
            if entry.expires_at and now > entry.expires_at:
                expired_keys.append(key)
        
        for key in expired_keys:
            self.remove_whitelist(key)
        
        return len(expired_keys)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get whitelist statistics."""
        now = time.time()
        
        stats = {
            "total_entries": len(self._entries),
            "ip_entries": 0,
            "pattern_entries": 0,
            "behavioral_entries": 0,
            "temporal_entries": 0,
            "ip_ranges": len(self._ip_ranges),
            "expired_entries": 0,
            "most_used_entries": []
        }
        
        for entry in self._entries.values():
            if entry.entry_type == WhitelistType.IP:
                stats["ip_entries"] += 1
            elif entry.entry_type == WhitelistType.PATTERN:
                stats["pattern_entries"] += 1
            elif entry.entry_type == WhitelistType.BEHAVIORAL:
                stats["behavioral_entries"] += 1
            elif entry.entry_type == WhitelistType.TEMPORAL:
                stats["temporal_entries"] += 1
            
            if entry.expires_at and now > entry.expires_at:
                stats["expired_entries"] += 1
        
        # Get most used entries
        sorted_entries = sorted(self._entries.values(), key=lambda e: e.usage_count, reverse=True)
        stats["most_used_entries"] = [
            {
                "value": entry.value,
                "type": entry.entry_type.value,
                "usage_count": entry.usage_count,
                "reason": entry.reason
            }
            for entry in sorted_entries[:5]
        ]
        
        return stats
    
    def export_whitelist(self) -> Dict[str, Any]:
        """Export whitelist for backup or migration."""
        return {
            "entries": {
                key: {
                    "entry_type": entry.entry_type.value,
                    "value": entry.value,
                    "confidence": entry.confidence,
                    "reason": entry.reason,
                    "created_at": entry.created_at,
                    "expires_at": entry.expires_at,
                    "usage_count": entry.usage_count,
                    "last_used": entry.last_used
                }
                for key, entry in self._entries.items()
            },
            "behavioral_baselines": self._behavioral_baselines,
            "temporal_patterns": self._temporal_patterns
        }
    
    def import_whitelist(self, data: Dict[str, Any]) -> bool:
        """Import whitelist from backup."""
        try:
            # Clear existing data
            self._entries.clear()
            self._ip_ranges.clear()
            self._pattern_cache.clear()
            self._behavioral_baselines.clear()
            self._temporal_patterns.clear()
            
            # Import entries
            for key, entry_data in data.get("entries", {}).items():
                entry = WhitelistEntry(
                    entry_type=WhitelistType(entry_data["entry_type"]),
                    value=entry_data["value"],
                    confidence=entry_data["confidence"],
                    reason=entry_data["reason"],
                    created_at=entry_data["created_at"],
                    expires_at=entry_data.get("expires_at"),
                    usage_count=entry_data.get("usage_count", 0),
                    last_used=entry_data.get("last_used")
                )
                self._entries[key] = entry
                
                # Rebuild caches
                if entry.entry_type == WhitelistType.IP and '/' in entry.value:
                    try:
                        network = ipaddress.IPv4Network(entry.value, strict=False)
                        self._ip_ranges.append((network, entry))
                    except (ipaddress.AddressValueError, ValueError):
                        pass
                elif entry.entry_type == WhitelistType.PATTERN:
                    try:
                        self._pattern_cache[entry.value] = re.compile(entry.value, re.IGNORECASE)
                    except re.error:
                        pass
            
            # Import behavioral baselines
            self._behavioral_baselines.update(data.get("behavioral_baselines", {}))
            
            # Import temporal patterns
            self._temporal_patterns.update(data.get("temporal_patterns", {}))
            
            return True
        except Exception:
            return False


# Global whitelist manager instance
whitelist_manager = WhitelistManager()


def is_whitelisted(ip: str, text: str = "", context: Dict[str, Any] = None) -> Tuple[bool, float, str]:
    """
    Convenience function to check if IP or text is whitelisted.
    
    Returns:
        Tuple of (is_whitelisted, confidence, reason)
    """
    return whitelist_manager.is_whitelisted(ip, text, context)


def add_ip_whitelist(ip: str, reason: str = "Manual whitelist", 
                    confidence: float = 1.0, expires_at: Optional[float] = None) -> bool:
    """Add IP to whitelist."""
    return whitelist_manager.add_ip_whitelist(ip, reason, confidence, expires_at)


def add_pattern_whitelist(pattern: str, reason: str = "Manual pattern whitelist",
                         confidence: float = 1.0, expires_at: Optional[float] = None) -> bool:
    """Add pattern to whitelist."""
    return whitelist_manager.add_pattern_whitelist(pattern, reason, confidence, expires_at)


def remove_whitelist(value: str) -> bool:
    """Remove whitelist entry."""
    return whitelist_manager.remove_whitelist(value)


def get_whitelist_statistics() -> Dict[str, Any]:
    """Get whitelist statistics."""
    return whitelist_manager.get_statistics()


def cleanup_expired_whitelist() -> int:
    """Cleanup expired whitelist entries."""
    return whitelist_manager.cleanup_expired()

