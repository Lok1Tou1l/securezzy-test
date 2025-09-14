from typing import Any, Dict, List


class InMemoryEventStore:
    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []

    def add(self, event: Dict[str, Any]) -> None:
        self._events.append(event)

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


event_store = InMemoryEventStore()


class InMemoryAlertStore:
    def __init__(self) -> None:
        self._alerts: List[Dict[str, Any]] = []

    def add(self, alert: Dict[str, Any]) -> None:
        self._alerts.append(alert)

    def get_all(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def clear(self) -> None:
        self._alerts.clear()


ddos_alert_store = InMemoryAlertStore()
injection_alert_store = InMemoryAlertStore()


