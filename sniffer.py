"""
Scapy-based packet sniffer that extracts minimal HTTP-like metadata and invokes a callback
with normalized events that our backend understands.

Notes:
- Requires administrative privileges to sniff on most systems.
- This is a best-effort parser for HTTP over TCP without reassembly; results may be partial.
"""

from typing import Callable, Dict, Any, Optional


try:
    from scapy.all import sniff, Packet  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover - allows running without scapy available
    sniff = None  # type: ignore
    Packet = object  # type: ignore
    IP = object  # type: ignore
    TCP = object  # type: ignore
    Raw = object  # type: ignore


def _parse_http_like_payload(payload_bytes: bytes) -> Dict[str, str]:
    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return {"method": "OTHER", "path": "/", "body": ""}

    # Simple request-line parse
    first_line = text.split("\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) >= 2 and parts[0] in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        method = parts[0]
        path = parts[1]
    else:
        method = "OTHER"
        path = "/"

    body = ""
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1][:512]

    return {"method": method, "path": path, "body": body}


def run_sniffer(
    callback: Callable[[Dict[str, Any]], None],
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = "tcp",
    timeout: Optional[int] = None,
    count: int = 0,
) -> None:
    """Start a scapy sniff loop and feed normalized events to the callback.

    Args:
        callback: Function receiving event dicts {source_ip, method, path, body}.
        iface: Network interface name to sniff on (None = default).
        bpf_filter: BPF filter string, default 'tcp'.
        timeout: Stop after N seconds (None = run indefinitely).
        count: Stop after N packets captured (0 = unlimited).
    """
    if sniff is None:
        raise RuntimeError("scapy is not available. Install it and run as admin/root.")

    def _handle(pkt: Packet) -> None:
        try:
            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            source_ip = getattr(ip_layer, "src", "unknown")

            method = "OTHER"
            path = "/"
            body = ""

            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                parsed = _parse_http_like_payload(raw)
                method = parsed["method"]
                path = parsed["path"]
                body = parsed["body"]

            event = {
                "source_ip": source_ip,
                "path": path,
                "method": method,
                "body": body,
            }
            callback(event)
        except Exception:
            # Keep the sniffer running even if a packet is malformed
            return

    sniff(prn=_handle, store=False, iface=iface, filter=bpf_filter, timeout=timeout, count=count)


