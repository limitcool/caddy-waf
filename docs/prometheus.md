# **Caddy WAF, Prometheus and Grafana**

Monitor your **caddy-waf** performance and security in real-time with **Prometheus** and **Grafana**. Track key metrics like allowed/blocked requests, rule hits (e.g., "block-scanners", "sql-injection", "xss-attacks", browser integrity checks), and more, to understand your WAF's effectiveness against threats.

This guide helps you create a **Prometheus exporter** to bridge Caddy WAF's JSON metrics (from `/waf_metrics`) to Prometheus's format. You'll then visualize these metrics in Grafana dashboards for actionable insights.

### **Step 1: Set Up Your Environment**

1.  **Install Python**: Get Python 3.x from [python.org](https://www.python.org/).

2.  **Install Libraries**:
    ```bash
    pip install prometheus-client requests
    ```

### **Step 2: Create the Exporter Script (exporter.py)**

```python
from prometheus_client import start_http_server, Counter, Gauge
import requests
import time
import json

# Define Prometheus metrics
TOTAL_REQUESTS = Counter('caddywaf_total_requests', 'Total requests processed')
BLOCKED_REQUESTS = Counter('caddywaf_blocked_requests', 'Total requests blocked')
ALLOWED_REQUESTS = Counter('caddywaf_allowed_requests', 'Total requests allowed')
RULE_HITS = Counter('caddywaf_rule_hits', 'Hits per WAF rule', ['rule_id'])
RULE_HITS_BY_PHASE = Counter('caddywaf_rule_hits_by_phase', 'Rule hits by phase', ['phase'])
DNS_BLACKLIST_HITS = Counter('caddywaf_dns_blacklist_hits', 'DNS blacklist hits')
GEOIP_BLOCKED = Counter('caddywaf_geoip_blocked', 'Blocked by GeoIP')
IP_BLACKLIST_HITS = Counter('caddywaf_ip_blacklist_hits', 'IP blacklist hits')
RATE_LIMITER_BLOCKED_REQUESTS = Counter('caddywaf_rate_limiter_blocked_requests', 'Rate limiter blocked')
RATE_LIMITER_REQUESTS = Counter('caddywaf_rate_limiter_requests', 'Rate limiter requests')
WAF_VERSION = Gauge('caddywaf_version', 'WAF version', ['version'])

def fetch_metrics():
    try:
        response = requests.get("http://localhost:8080/waf_metrics")
        response.raise_for_status()
        data = response.json()

        TOTAL_REQUESTS.inc(data["total_requests"])
        BLOCKED_REQUESTS.inc(data["blocked_requests"])
        ALLOWED_REQUESTS.inc(data["allowed_requests"])
        DNS_BLACKLIST_HITS.inc(data["dns_blacklist_hits"])
        GEOIP_BLOCKED.inc(data["geoip_blocked"])
        IP_BLACKLIST_HITS.inc(data["ip_blacklist_hits"])
        RATE_LIMITER_BLOCKED_REQUESTS.inc(data["rate_limiter_blocked_requests"])
        RATE_LIMITER_REQUESTS.inc(data["rate_limiter_requests"])
        WAF_VERSION.labels(version=data["version"]).set(1)

        for rule_id, hits in data["rule_hits"].items():
            RULE_HITS.labels(rule_id=rule_id).inc(hits)

        if "rule_hits_by_phase" in data:
            for phase, hits in data["rule_hits_by_phase"].items():
                RULE_HITS_BY_PHASE.labels(phase=phase).inc(hits)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching metrics: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")

if __name__ == '__main__':
    start_http_server(8000)
    print("Exporter started on http://localhost:8000/metrics")
    while True:
        fetch_metrics()
        time.sleep(10)
```

### **Step 3: Run the Exporter**

1.  Start: `python exporter.py`
2.  Verify: `http://localhost:8000/metrics` in browser. Check for Prometheus format.

    Example output snippet:
    ```
    # HELP caddywaf_rule_hits_by_phase Rule hits by phase
    # TYPE caddywaf_rule_hits_by_phase counter
    caddywaf_rule_hits_by_phase{phase="1"} 1461
    caddywaf_rule_hits_by_phase{phase="2"} 705
    ```

### **Step 4: Configure Prometheus**

1.  Install: [prometheus.io/download/](https://prometheus.io/download/)
2.  Edit `prometheus.yml`:

    ```yaml
    scrape_configs:
      - job_name: 'caddywaf_exporter'
        static_configs:
          - targets: ['localhost:8000']
    ```

3.  Start: `./prometheus --config.file=prometheus.yml`
4.  Verify: Prometheus UI (`http://localhost:9090`) > Status > Targets > `caddywaf_exporter` should be UP.

### **Step 5: Set Up Grafana**

1.  Install: [grafana.com/grafana/download](https://grafana.com/grafana/download)
2.  Start: `http://localhost:3000` (login: `admin/admin`)
3.  Add Data Source: Configuration > Data Sources > Add data source > Prometheus. URL: `http://localhost:9090`. Save & Test.
4.  Create Dashboard: Create > Dashboard > Add panel. Example queries:

    *   **Total Requests:** `sum(rate(caddywaf_total_requests[1m]))`
    *   **Blocked Requests:** `sum(rate(caddywaf_blocked_requests[1m]))`
    *   **Top Rule Hits:** `topk(10, sum by (rule_id) (rate(caddywaf_rule_hits[1m])))`
    *   **Rule Hits by Phase:** `sum by (phase) (rate(caddywaf_rule_hits_by_phase[1m]))`
    *   **WAF Version:** `caddywaf_version`

    Customize dashboards as needed.

### **Step 6: Run Everything Together**

1.  Start Caddy WAF (`/waf_metrics` accessible).
2.  Start Exporter: `python exporter.py`
3.  Start Prometheus (with config).
4.  Start Grafana (connected to Prometheus).
5.  Visualize metrics in Grafana.

---

### **Optional: Exporter as Service (systemd)**

1.  Create: `sudo nano /etc/systemd/system/caddywaf-exporter.service`

2.  Content:
    ```ini
    [Unit]
    Description=Caddy WAF Prometheus Exporter
    After=network.target

    [Service]
    User=your_user
    ExecStart=/usr/bin/python3 /path/to/exporter.py
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```

3.  Run:
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl start caddywaf-exporter
    sudo systemctl enable caddywaf-exporter
    ```

4.  Verify: `sudo systemctl status caddywaf-exporter`
