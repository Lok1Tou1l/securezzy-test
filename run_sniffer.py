import os
import sys
from typing import Dict, Any

import requests
from dotenv import load_dotenv

from sniffer import run_sniffer


API_BASE = os.environ.get("SECUREZZY_API", "http://127.0.0.1:5000")


def forward_to_api(event: Dict[str, Any]) -> None:
    try:
        requests.post(f"{API_BASE}/events", json=event, timeout=1)
    except Exception:
        # Avoid crashing the sniffer on transient network/API issues
        pass


def main() -> int:
    # Load environment from .env if present
    load_dotenv()
    # Example defaults: sniff TCP traffic on common HTTP(S) ports
    bpf = os.environ.get("SECUREZZY_BPF", "tcp port 80 or tcp port 443")
    iface = os.environ.get("SECUREZZY_IFACE") or None
    try:
        run_sniffer(callback=forward_to_api, iface=iface, bpf_filter=bpf, timeout=None, count=0)
    except KeyboardInterrupt:
        return 0
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())


