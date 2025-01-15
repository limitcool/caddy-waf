## Your WAF log with Prometheus and Grafana

### **Introduction**

If you're running a **Caddy Web Application Firewall (WAF)**, you likely want to monitor its performance and security metrics in real-time. Metrics like the number of allowed/blocked requests, rule hits, and other key indicators can help you understand how your WAF is performing and identify potential threats.

To achieve this, you can use **Prometheus** (a powerful time-series database for metrics) and **Grafana** (a visualization tool) to collect, store, and visualize your WAF metrics. However, Prometheus requires metrics to be exposed in a specific format. Since your Caddy WAF already exposes metrics in JSON format via the `/waf_metrics` endpoint, we need a way to convert this JSON data into a format that Prometheus can scrape.

This is where a **Prometheus exporter** comes in. An exporter acts as a bridge between your application and Prometheus, converting your application's metrics into Prometheus-compatible metrics.

In this step-by-step guide, I'll walk you through creating and running a **Prometheus exporter** for your Caddy WAF. By the end, you'll have a fully functional exporter that scrapes your `/waf_metrics` endpoint, converts the JSON data into Prometheus metrics, and exposes them for scraping.

---

### **What You'll Learn**

1. How to create a **Prometheus exporter** in Python.
2. How to configure **Prometheus** to scrape metrics from the exporter.
3. How to set up **Grafana** to visualize your WAF metrics.
4. How to run the exporter as a **systemd service** for continuous operation.

---

### **Prerequisites**

Before we begin, ensure you have the following:

1. **Caddy WAF** running and exposing the `/waf_metrics` endpoint.
2. **Python 3.x** installed on your system.
3. **Prometheus** installed and running.
4. **Grafana** installed and running.
5. Basic familiarity with the command line and Python.

---

### **Step-by-Step Guide**

Now that we've set the stage, let’s dive into the step-by-step guide! 🚀

---

### **Step 1: Set Up Your Environment**

1. **Install Python**:
   - Ensure Python 3.x is installed on your system. You can download it from [python.org](https://www.python.org/).

2. **Install Required Libraries**:
   - Install the `prometheus-client` and `requests` libraries using pip:
     ```bash
     pip install prometheus-client requests
     ```

---

### **Step 2: Create the Exporter Script**

1. Create a new file named `exporter.py`:

   ```python
   from prometheus_client import start_http_server, Counter, Gauge
   import requests
   import time

   # Define Prometheus metrics
   TOTAL_REQUESTS = Counter('caddywaf_total_requests', 'Total number of requests processed by the WAF')
   BLOCKED_REQUESTS = Counter('caddywaf_blocked_requests', 'Total number of requests blocked by the WAF')
   ALLOWED_REQUESTS = Counter('caddywaf_allowed_requests', 'Total number of requests allowed by the WAF')
   RULE_HITS = Counter('caddywaf_rule_hits', 'Total number of hits per WAF rule', ['rule_id'])

   def fetch_metrics():
       # Fetch metrics from the Caddy WAF /waf_metrics endpoint
       response = requests.get("http://localhost:8080/waf_metrics")
       data = response.json()

       # Update Prometheus metrics
       TOTAL_REQUESTS.inc(data["total_requests"])
       BLOCKED_REQUESTS.inc(data["blocked_requests"])
       ALLOWED_REQUESTS.inc(data["allowed_requests"])

       for rule_id, hits in data["rule_hits"].items():
           RULE_HITS.labels(rule_id=rule_id).inc(hits)

   if __name__ == '__main__':
       # Start the Prometheus HTTP server on port 8000
       start_http_server(8000)
       print("Exporter started on http://localhost:8000/metrics")

       # Fetch metrics every 10 seconds
       while True:
           fetch_metrics()
           time.sleep(10)
   ```

---

### **Step 3: Run the Exporter**

1. Start the exporter:
   ```bash
   python exporter.py
   ```

2. Verify that the exporter is running:
   - Open your browser and go to `http://localhost:8000/metrics`.
   - You should see Prometheus-formatted metrics like this:
     ```
     # HELP caddywaf_total_requests Total number of requests processed by the WAF.
     # TYPE caddywaf_total_requests counter
     caddywaf_total_requests 212

     # HELP caddywaf_blocked_requests Total number of requests blocked by the WAF.
     # TYPE caddywaf_blocked_requests counter
     caddywaf_blocked_requests 166

     # HELP caddywaf_allowed_requests Total number of requests allowed by the WAF.
     # TYPE caddywaf_allowed_requests counter
     caddywaf_allowed_requests 46

     # HELP caddywaf_rule_hits Total number of hits per WAF rule.
     # TYPE caddywaf_rule_hits counter
     caddywaf_rule_hits{rule_id="942440"} 1
     caddywaf_rule_hits{rule_id="block-scanners"} 13
     ```

---

### **Step 4: Configure Prometheus**

1. **Install Prometheus**:
   - Download Prometheus from [prometheus.io](https://prometheus.io/download/).
   - Extract the archive and navigate to the Prometheus directory.

2. **Edit `prometheus.yml`**:
   - Open the `prometheus.yml` file in a text editor.
   - Add a scrape configuration for the exporter:
     ```yaml
     scrape_configs:
       - job_name: 'caddywaf_exporter'
         static_configs:
           - targets: ['localhost:8000']
     ```

3. **Start Prometheus**:
   - Run Prometheus:
     ```bash
     ./prometheus --config.file=prometheus.yml
     ```

4. **Verify Prometheus**:
   - Open your browser and go to `http://localhost:9090`.
   - In the Prometheus UI, go to **Status > Targets** and verify that the exporter is listed as "UP".

---

### **Step 5: Set Up Grafana**

1. **Install Grafana**:
   - Download Grafana from [grafana.com](https://grafana.com/grafana/download).
   - Follow the installation instructions for your operating system.

2. **Start Grafana**:
   - Start the Grafana server:
     ```bash
     systemctl start grafana-server
     ```
   - Open your browser and go to `http://localhost:3000`.

3. **Add Prometheus as a Data Source**:
   - Log in to Grafana (default username/password: `admin/admin`).
   - Go to **Configuration > Data Sources**.
   - Click **Add data source** and select **Prometheus**.
   - Set the URL to `http://localhost:9090` and click **Save & Test**.

4. **Create a Dashboard**:
   - Go to **Create > Dashboard**.
   - Add a new panel and use the following queries:
     - `caddywaf_total_requests`
     - `caddywaf_blocked_requests`
     - `caddywaf_allowed_requests`
     - `caddywaf_rule_hits`
   - Customize the panels (e.g., use graphs, gauges, or tables).

---

### **Step 6: Run Everything Together**

1. **Start Caddy WAF**:
   - Ensure your Caddy WAF is running and exposing the `/waf_metrics` endpoint.

2. **Start the Exporter**:
   - Run the exporter script:
     ```bash
     python exporter.py
     ```

3. **Start Prometheus**:
   - Run Prometheus with the updated configuration.

4. **Start Grafana**:
   - Ensure Grafana is running and configured to use Prometheus as a data source.

5. **Visualize Metrics**:
   - Use Grafana to create dashboards and visualize your Caddy WAF metrics.

---

### **Optional: Run the Exporter as a Service**

To ensure the exporter runs continuously, you can set it up as a systemd service.

1. Create a service file:
   ```bash
   sudo nano /etc/systemd/system/caddywaf-exporter.service
   ```

2. Add the following content:
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

3. Reload systemd and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start caddywaf-exporter
   sudo systemctl enable caddywaf-exporter
   ```

4. Verify the service is running:
   ```bash
   sudo systemctl status caddywaf-exporter
   ```

---

### **Conclusion**

You now have a fully functional Prometheus exporter for your Caddy WAF metrics! This setup allows you to scrape, store, and visualize your WAF metrics using Prometheus and Grafana. 
