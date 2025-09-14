# Securezzy Test

A minimal demo app with a Flask API, basic DDoS and injection detection, a tiny frontend, and tests.

## Quickstart

1. Create a virtualenv and install dependencies
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the API
```bash
python app.py
```

3. Open the frontend
- Serve the `frontend/` folder with any static server or open `frontend/index.html` directly. For best results, open in the same origin as the API or adjust CORS.

4. (Optional) Run the packet sniffer and stream live data
```bash
# Requires admin/root to sniff. Customize interface and filter if needed.
copy ENV_TEMPLATE .env
# Edit .env if needed, then:
pip install -r requirements.txt
python run_sniffer.py
```
The dashboard will update in real time via `GET /stream/events`.

## API
- `GET /health` → `{ status: "ok" }`
- `GET /events` → returns stored events
- `POST /events` with JSON `{ source_ip, path, method, body }` → stores event and returns detection flags

## Detection
- DDoS: naive sliding-window per-IP counter (window 10s, threshold >20)
- Injection: regex-based signatures defined in `utils/regex_patterns.py`

## Tests
Run tests:
```bash
pytest -q
```

## Notes
- Scapy sniffing often needs elevated privileges.
- HTTPS payloads are encrypted; only metadata like source IP is visible without TLS termination.
- This is a demo; do not use as-is for production security monitoring.
