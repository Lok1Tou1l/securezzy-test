from typing import Any, Dict, List, Optional
import json
import os
import time
import sqlite3
from datetime import datetime
from enum import Enum


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogType(Enum):
    SYSTEM = "system"
    SECURITY = "security"
    DDoS = "ddos"
    INJECTION = "injection"
    NETWORK = "network"
    API = "api"
    DATABASE = "database"
    AUTH = "auth"


class InMemoryEventStore:
    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def add(self, event: Dict[str, Any]) -> None:
        self._events.append(event)

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._events)

    def get_events(self, event_type: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """Get events, optionally filtered by type and limited in count"""
        events = self._events
        
        if event_type:
            events = [e for e in events if e.get('type') == event_type]
        
        if limit:
            events = events[-limit:]
        
        return events

    def clear(self) -> None:
        self._events.clear()


class InMemoryAlertStore:
    def __init__(self) -> None:
        self._alerts: List[Dict[str, Any]] = []

    def add(self, alert: Dict[str, Any]) -> None:
        self._alerts.append(alert)

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def clear(self) -> None:
        self._alerts.clear()


class LogEntry:
    def __init__(self, level: LogLevel, log_type: LogType, message: str, 
                 source: str = "system", details: Dict[str, Any] = None):
        self.timestamp = time.time()
        self.datetime = datetime.now().isoformat()
        self.level = level.value
        self.log_type = log_type.value
        self.message = message
        self.source = source
        self.details = details or {}
        self.id = f"{self.timestamp}_{hash(message) % 10000}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'datetime': self.datetime,
            'level': self.level,
            'log_type': self.log_type,
            'message': self.message,
            'source': self.source,
            'details': self.details
        }


class LogStore:
    def __init__(self, max_entries: int = 10000):
        self.max_entries = max_entries
        self.db_path = "logs.db"
        self._setup_database()

    def _setup_database(self):
        """Setup SQLite database for logs with separate tables"""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs("logs", exist_ok=True)
            
            # Connect to SQLite database
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Create main logs table
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id TEXT PRIMARY KEY,
                    timestamp REAL,
                    datetime TEXT,
                    level TEXT,
                    log_type TEXT,
                    message TEXT,
                    source TEXT,
                    details TEXT
                )
            ''')
            
            # Create DDoS-specific logs table
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS ddos_logs (
                    id TEXT PRIMARY KEY,
                    timestamp REAL,
                    datetime TEXT,
                    level TEXT,
                    source_ip TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    severity TEXT,
                    request_count INTEGER,
                    time_window REAL,
                    user_agent TEXT,
                    country TEXT,
                    path TEXT,
                    method TEXT,
                    details TEXT
                )
            ''')
            
            # Create injection-specific logs table
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS injection_logs (
                    id TEXT PRIMARY KEY,
                    timestamp REAL,
                    datetime TEXT,
                    level TEXT,
                    source_ip TEXT,
                    attack_type TEXT,
                    confidence REAL,
                    payload TEXT,
                    endpoint TEXT,
                    parameter TEXT,
                    method TEXT,
                    user_agent TEXT,
                    country TEXT,
                    details TEXT
                )
            ''')
            
            # Create security-specific logs table
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS security_logs (
                    id TEXT PRIMARY KEY,
                    timestamp REAL,
                    datetime TEXT,
                    level TEXT,
                    event_type TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    country TEXT,
                    endpoint TEXT,
                    method TEXT,
                    threat_level TEXT,
                    details TEXT
                )
            ''')
            
            self.conn.commit()
            print(f"✅ SQLite logging database initialized with separate tables: {self.db_path}")
        except Exception as e:
            print(f"Warning: Could not setup SQLite database: {e}")
            self.conn = None

    def add_log(self, level: LogLevel, log_type: LogType, message: str, 
                source: str = "system", details: Dict[str, Any] = None):
        """Add a new log entry"""
        log_entry = LogEntry(level, log_type, message, source, details)
        
        # Save to SQLite database
        if self.conn:
            try:
                self.conn.execute('''
                    INSERT OR REPLACE INTO logs 
                    (id, timestamp, datetime, level, log_type, message, source, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log_entry.id,
                    log_entry.timestamp,
                    log_entry.datetime,
                    log_entry.level,
                    log_entry.log_type,
                    log_entry.message,
                    log_entry.source,
                    json.dumps(log_entry.details)
                ))
                self.conn.commit()
                
                # Maintain max entries limit
                self.conn.execute('''
                    DELETE FROM logs WHERE id NOT IN (
                        SELECT id FROM logs ORDER BY timestamp DESC LIMIT ?
                    )
                ''', (self.max_entries,))
                self.conn.commit()
            except Exception as e:
                print(f"Warning: Could not save log to database: {e}")
        
        return log_entry

    def add_ddos_log(self, level: LogLevel, source_ip: str, attack_type: str, 
                     confidence: float, severity: str, request_count: int = 0,
                     time_window: float = 0, user_agent: str = "", country: str = "",
                     path: str = "", method: str = "", details: Dict[str, Any] = None):
        """Add a DDoS-specific log entry"""
        if not self.conn:
            return None
        
        try:
            log_id = f"{time.time()}_{id(self)}"
            timestamp = time.time()
            datetime_str = datetime.fromtimestamp(timestamp).isoformat()
            
            self.conn.execute('''
                INSERT OR REPLACE INTO ddos_logs 
                (id, timestamp, datetime, level, source_ip, attack_type, confidence, 
                 severity, request_count, time_window, user_agent, country, path, method, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id, timestamp, datetime_str, level.value, source_ip, attack_type,
                confidence, severity, request_count, time_window, user_agent, country,
                path, method, json.dumps(details or {})
            ))
            self.conn.commit()
            
            # Also add to main logs table
            self.add_log(level, LogType.DDoS, f"DDoS {attack_type} detected from {source_ip}", 
                        "ddos_detector", details)
            
            return log_id
        except Exception as e:
            print(f"Warning: Could not save DDoS log to database: {e}")
            return None

    def add_injection_log(self, level: LogLevel, source_ip: str, attack_type: str,
                         confidence: float, payload: str, endpoint: str = "",
                         parameter: str = "", method: str = "", user_agent: str = "",
                         country: str = "", details: Dict[str, Any] = None):
        """Add an injection-specific log entry"""
        if not self.conn:
            return None
        
        try:
            log_id = f"{time.time()}_{id(self)}"
            timestamp = time.time()
            datetime_str = datetime.fromtimestamp(timestamp).isoformat()
            
            self.conn.execute('''
                INSERT OR REPLACE INTO injection_logs 
                (id, timestamp, datetime, level, source_ip, attack_type, confidence,
                 payload, endpoint, parameter, method, user_agent, country, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id, timestamp, datetime_str, level.value, source_ip, attack_type,
                confidence, payload, endpoint, parameter, method, user_agent, country,
                json.dumps(details or {})
            ))
            self.conn.commit()
            
            # Also add to main logs table
            self.add_log(level, LogType.INJECTION, f"Injection {attack_type} detected from {source_ip}", 
                        "injection_detector", details)
            
            return log_id
        except Exception as e:
            print(f"Warning: Could not save injection log to database: {e}")
            return None

    def add_security_log(self, level: LogLevel, event_type: str, source_ip: str,
                        user_agent: str = "", country: str = "", endpoint: str = "",
                        method: str = "", threat_level: str = "medium",
                        details: Dict[str, Any] = None):
        """Add a security-specific log entry"""
        if not self.conn:
            return None
        
        try:
            log_id = f"{time.time()}_{id(self)}"
            timestamp = time.time()
            datetime_str = datetime.fromtimestamp(timestamp).isoformat()
            
            self.conn.execute('''
                INSERT OR REPLACE INTO security_logs 
                (id, timestamp, datetime, level, event_type, source_ip, user_agent,
                 country, endpoint, method, threat_level, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id, timestamp, datetime_str, level.value, event_type, source_ip,
                user_agent, country, endpoint, method, threat_level, json.dumps(details or {})
            ))
            self.conn.commit()
            
            # Also add to main logs table
            self.add_log(level, LogType.SECURITY, f"Security event: {event_type} from {source_ip}", 
                        "security_monitor", details)
            
            return log_id
        except Exception as e:
            print(f"Warning: Could not save security log to database: {e}")
            return None

    def get_logs(self, log_type: Optional[str] = None, level: Optional[str] = None, 
                 source: Optional[str] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get logs with optional filtering"""
        if not self.conn:
            return []
        
        try:
            # Build query
            query = "SELECT * FROM logs WHERE 1=1"
            params = []
            
            if log_type:
                query += " AND log_type = ?"
                params.append(log_type)
            
            if level:
                query += " AND level = ?"
                params.append(level)
            
            if source:
                query += " AND source = ?"
                params.append(source)
            
            query += " ORDER BY timestamp DESC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'datetime': row[2],
                    'level': row[3],
                    'log_type': row[4],
                    'message': row[5],
                    'source': row[6],
                    'details': json.loads(row[7]) if row[7] else {}
                })
            
            return logs
        except Exception as e:
            print(f"Warning: Could not retrieve logs from database: {e}")
            return []

    def get_ddos_logs(self, limit: Optional[int] = None, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get DDoS logs with optional filtering"""
        if not self.conn:
            return []
        
        try:
            query = "SELECT * FROM ddos_logs WHERE 1=1"
            params = []
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            query += " ORDER BY timestamp DESC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'datetime': row[2],
                    'level': row[3],
                    'source_ip': row[4],
                    'attack_type': row[5],
                    'confidence': row[6],
                    'severity': row[7],
                    'request_count': row[8],
                    'time_window': row[9],
                    'user_agent': row[10],
                    'country': row[11],
                    'path': row[12],
                    'method': row[13],
                    'details': json.loads(row[14]) if row[14] else {}
                })
            
            return logs
        except Exception as e:
            print(f"Warning: Could not retrieve DDoS logs: {e}")
            return []

    def get_injection_logs(self, limit: Optional[int] = None, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get injection logs with optional filtering"""
        if not self.conn:
            return []
        
        try:
            query = "SELECT * FROM injection_logs WHERE 1=1"
            params = []
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            query += " ORDER BY timestamp DESC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'datetime': row[2],
                    'level': row[3],
                    'source_ip': row[4],
                    'attack_type': row[5],
                    'confidence': row[6],
                    'payload': row[7],
                    'endpoint': row[8],
                    'parameter': row[9],
                    'method': row[10],
                    'user_agent': row[11],
                    'country': row[12],
                    'details': json.loads(row[13]) if row[13] else {}
                })
            
            return logs
        except Exception as e:
            print(f"Warning: Could not retrieve injection logs: {e}")
            return []

    def get_security_logs(self, limit: Optional[int] = None, source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get security logs with optional filtering"""
        if not self.conn:
            return []
        
        try:
            query = "SELECT * FROM security_logs WHERE 1=1"
            params = []
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            query += " ORDER BY timestamp DESC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'datetime': row[2],
                    'level': row[3],
                    'event_type': row[4],
                    'source_ip': row[5],
                    'user_agent': row[6],
                    'country': row[7],
                    'endpoint': row[8],
                    'method': row[9],
                    'threat_level': row[10],
                    'details': json.loads(row[11]) if row[11] else {}
                })
            
            return logs
        except Exception as e:
            print(f"Warning: Could not retrieve security logs: {e}")
            return []

    def get_logs_by_time_range(self, start_time: float, end_time: float) -> List[Dict[str, Any]]:
        """Get logs within a time range"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.execute('''
                SELECT * FROM logs 
                WHERE timestamp BETWEEN ? AND ? 
                ORDER BY timestamp DESC
            ''', (start_time, end_time))
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'datetime': row[2],
                    'level': row[3],
                    'log_type': row[4],
                    'message': row[5],
                    'source': row[6],
                    'details': json.loads(row[7]) if row[7] else {}
                })
            
            return logs
        except Exception as e:
            print(f"Warning: Could not retrieve logs by time range: {e}")
            return []

    def clear_logs(self):
        """Clear all logs from all tables"""
        if self.conn:
            try:
                self.conn.execute('DELETE FROM logs')
                self.conn.execute('DELETE FROM ddos_logs')
                self.conn.execute('DELETE FROM injection_logs')
                self.conn.execute('DELETE FROM security_logs')
                self.conn.commit()
                print("✅ All logs cleared from database")
            except Exception as e:
                print(f"Warning: Could not clear logs from database: {e}")

    def get_log_statistics(self) -> Dict[str, Any]:
        """Get statistics about the logs"""
        if not self.conn:
            return {
                'total_logs': 0,
                'by_level': {},
                'by_type': {},
                'by_source': {},
                'oldest_log': None,
                'newest_log': None
            }
        
        try:
            # Get total count from all tables
            cursor = self.conn.execute('SELECT COUNT(*) FROM logs')
            total_logs = cursor.fetchone()[0]
            
            cursor = self.conn.execute('SELECT COUNT(*) FROM ddos_logs')
            total_ddos_logs = cursor.fetchone()[0]
            
            cursor = self.conn.execute('SELECT COUNT(*) FROM injection_logs')
            total_injection_logs = cursor.fetchone()[0]
            
            cursor = self.conn.execute('SELECT COUNT(*) FROM security_logs')
            total_security_logs = cursor.fetchone()[0]
            
            # Get counts by level from main logs table
            cursor = self.conn.execute('SELECT level, COUNT(*) FROM logs GROUP BY level')
            by_level = dict(cursor.fetchall())
            
            # Get counts by type from main logs table
            cursor = self.conn.execute('SELECT log_type, COUNT(*) FROM logs GROUP BY log_type')
            by_type = dict(cursor.fetchall())
            
            # Get counts by source from main logs table
            cursor = self.conn.execute('SELECT source, COUNT(*) FROM logs GROUP BY source')
            by_source = dict(cursor.fetchall())
            
            # Get oldest and newest timestamps from main logs table
            cursor = self.conn.execute('SELECT MIN(datetime), MAX(datetime) FROM logs')
            result = cursor.fetchone()
            oldest_log = result[0] if result[0] else None
            newest_log = result[1] if result[1] else None
            
            return {
                'total_logs': total_logs,
                'total_ddos_logs': total_ddos_logs,
                'total_injection_logs': total_injection_logs,
                'total_security_logs': total_security_logs,
                'by_level': by_level,
                'by_type': by_type,
                'by_source': by_source,
                'oldest_log': oldest_log,
                'newest_log': newest_log
            }
        except Exception as e:
            print(f"Warning: Could not get log statistics: {e}")
            return {
                'total_logs': 0,
                'by_level': {},
                'by_type': {},
                'by_source': {},
                'oldest_log': None,
                'newest_log': None
            }


# Initialize stores
event_store = InMemoryEventStore()
ddos_alert_store = InMemoryAlertStore()
injection_alert_store = InMemoryAlertStore()
log_store = LogStore()

# Convenience functions for logging
def log_info(message: str, log_type: LogType = LogType.SYSTEM, source: str = "system", details: Dict[str, Any] = None):
    return log_store.add_log(LogLevel.INFO, log_type, message, source, details)

def log_warning(message: str, log_type: LogType = LogType.SYSTEM, source: str = "system", details: Dict[str, Any] = None):
    return log_store.add_log(LogLevel.WARNING, log_type, message, source, details)

def log_error(message: str, log_type: LogType = LogType.SYSTEM, source: str = "system", details: Dict[str, Any] = None):
    return log_store.add_log(LogLevel.ERROR, log_type, message, source, details)

def log_critical(message: str, log_type: LogType = LogType.SYSTEM, source: str = "system", details: Dict[str, Any] = None):
    return log_store.add_log(LogLevel.CRITICAL, log_type, message, source, details)

def log_debug(message: str, log_type: LogType = LogType.SYSTEM, source: str = "system", details: Dict[str, Any] = None):
    return log_store.add_log(LogLevel.DEBUG, log_type, message, source, details)

# Specialized logging functions
def log_ddos_attack(source_ip: str, attack_type: str, confidence: float, severity: str,
                   request_count: int = 0, time_window: float = 0, user_agent: str = "",
                   country: str = "", path: str = "", method: str = "", details: Dict[str, Any] = None):
    """Log a DDoS attack"""
    if STORAGE_AVAILABLE:
        level = LogLevel.CRITICAL if confidence > 0.8 else LogLevel.WARNING
        return log_store.add_ddos_log(level, source_ip, attack_type, confidence, severity,
                                     request_count, time_window, user_agent, country, path, method, details)
    return None

def log_injection_attack(source_ip: str, attack_type: str, confidence: float, payload: str,
                        endpoint: str = "", parameter: str = "", method: str = "",
                        user_agent: str = "", country: str = "", details: Dict[str, Any] = None):
    """Log an injection attack"""
    if STORAGE_AVAILABLE:
        level = LogLevel.CRITICAL if confidence > 0.8 else LogLevel.WARNING
        return log_store.add_injection_log(level, source_ip, attack_type, confidence, payload,
                                          endpoint, parameter, method, user_agent, country, details)
    return None

def log_security_event(event_type: str, source_ip: str, user_agent: str = "", country: str = "",
                      endpoint: str = "", method: str = "", threat_level: str = "medium",
                      details: Dict[str, Any] = None):
    """Log a security event"""
    if STORAGE_AVAILABLE:
        level = LogLevel.CRITICAL if threat_level == "high" else LogLevel.WARNING
        return log_store.add_security_log(level, event_type, source_ip, user_agent, country,
                                         endpoint, method, threat_level, details)
    return None


