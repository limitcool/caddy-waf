# caddytest.py

This is Python script designed to send HTTP requests that mimic both legitimate and malicious traffic. It is primarily intended to trigger Web Application Firewall (WAF) rules by simulating various attack vectors while also providing advanced metrics and behavior profiles to emulate realistic attacker activity.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Behavior Profiles](#behavior-profiles)
  - [Examples](#examples)
- [Output and Metrics](#output-and-metrics)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This script allows you to simulate different types of attacks against a target URL. It sends HTTP requests with a mix of malicious payloads (SQL injection, XSS, command injection, local file inclusion, remote code execution, etc.) and legitimate parameters to test and trigger WAF rules. The script supports:

- A wide range of attack payloads across multiple vectors.
- Composite payloads combining legitimate and malicious data.
- Configurable behavior profiles to simulate burst, calm, or stealthy attack patterns.
- Detailed metrics collection and output summarizing latency, response sizes, status code distribution, and more.
- High concurrency with multithreading and customizable retry logic.

---

## Features

- **Multiple Attack Types:** Supports SQLi, XSS, CMD injection, LFI, RCE, CRLF, SSRF, XXE, XPath, NoSQL, HTTP smuggling, Shellshock, LDAP, and RFI.
- **Composite Requests:** Merge legitimate traffic with malicious payloads.
- **Behavior Profiles:** Simulate various attacker behaviors (e.g., burst then calm, stealth scanning).
- **Randomization Options:** Random HTTP methods, random path segments, random cookie headers, and more.
- **Retry Logic:** Configurable number of retries with delay between attempts.
- **Concurrency:** Send requests in parallel using configurable thread count.
- **Advanced Metrics:** Collects latency (avg, median, percentiles, standard deviation), response size metrics, and status code distributions.
- **JSON Summary Output:** Optionally save a JSON summary file with detailed metrics.
- **Customizable Options:** All aspects of request composition, timing, and behavior are configurable via command-line arguments.

---

## Installation

### Prerequisites

- **Python 3.x**  
- **pip** (Python package installer)

### Required Packages

Install the necessary Python packages using pip:

```bash
pip install requests tqdm
```

## Usage

Run the script from the repository folder by using Python. The configuration is done via command-line options.

```bash
python3 caddytest.py [OPTIONS]
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--url` | `http://localhost:8080` | Target base URL. |
| `--method` | `GET` | Default HTTP method to use (choices: GET, POST, PUT, DELETE, OPTIONS). |
| `--num-requests` | `100` | Total number of requests to send. |
| `--delay` | `1.0` | Base delay between requests in seconds. |
| `--delay-jitter` | `0.0` | Maximum jitter (+/-) added to the delay. |
| `--attack-type` | `all` | Attack payload type (choose one of the keys from the payload dictionary, or "all"). |
| `--legit-percent` | `0.0` | Percentage of requests that are legitimate (0–100). |
| `--composite` | _False_ | Compose requests with both legitimate and malicious parameters. |
| `--max-errors` | `3` | Maximum errors before exiting. |
| `--timeout` | `5.0` | HTTP request timeout in seconds. |
| `--max-retries` | `0` | Maximum number of retries for a failed request. |
| `--retry-delay` | `0.1` | Delay between retries in seconds. |
| `--seed` | _None_ | Random seed for reproducibility. |
| `--proxy` | _None_ | Proxy URL to route requests through (e.g., `http://127.0.0.1:8080`). |
| `--threads` | `1` | Number of concurrent threads. |
| `--random-method` | _False_ | Select a random HTTP method per request. |
| `--random-cookies` | _False_ | Include random cookie headers. |
| `--random-path` | _False_ | Append a random path segment to the base URL. |
| `--json` | _False_ | Send payload as JSON instead of form data. |
| `--log-file` | _None_ | File to write log output. |
| `--progress` | _False_ | Display a progress bar (requires `tqdm`). |
| `--score` | _False_ | Compute overall test score based on expected status codes. |
| `--expected-status-legit` | `200` | Expected status code for legitimate requests. |
| `--expected-status-malicious` | `403` | Expected status code for malicious requests. |
| `--expected-status-composite` | `200` | Expected status code for composite requests. |
| `--behavior` | `default` | Behavior profile: `default`, `burst_calm`, or `stealth`. |
| `--insecure` | _False_ | Disable SSL certificate verification. |
| `--json-summary-file` | _None_ | File path to output JSON summary of the test. |

### Behavior Profiles

The script supports several behavior profiles to simulate different attack patterns:

- **default**: Uses the specified parameters without modification.
- **burst_calm**:  
  - **Burst phase** (first 30%): Rapid requests with all malicious payloads and minimal delay.  
  - **Calm phase** (next 30%): Slower request rate with original legitimate percentage and increased delay.  
  - **Scanning phase** (last 40%): Simulates path scanning by forcing GET requests to endpoints like `/admin`, `/config`, `/login`, etc.
- **stealth**: Mimics a stealthy attacker by increasing the percentage of legitimate requests, slowing down the pace, and typically using only GET/POST methods.

---

## Examples

### Example 1: Basic Usage

Send 1000 requests using the default settings:

```bash
python3 caddytest.py --num-requests 1000
```

### Example 2: High Legitimate Traffic in Stealth Mode

Simulate 1000 requests with 100% legitimate traffic in stealth mode using 4 threads and no delay:

```bash
python3 caddytest.py --num-requests 1000 --threads 4 --delay 0 --legit-percent 100 --behavior stealth --progress
```

### Example 3: Burst/Calm Behavior with Composite Payloads

Send 500 requests with composite payloads and a burst then calm behavior pattern:

```bash
python3 caddytest.py --num-requests 500 --composite --behavior burst_calm --progress
```

### Example 4: Using Random Methods and Cookies with JSON Summary

Send 200 requests using random HTTP methods and include random cookie headers; output the summary in JSON format:

```bash
python3 caddytest.py --num-requests 200 --random-method --random-cookies --json-summary-file summary.json --progress
```

---

## Output and Metrics

After execution, the script prints a detailed summary that includes:

- **Total Requests:** Number of requests sent.
- **Passed / Errors:** Count and percentage of successful and failed requests.
- **Latency Metrics:** Average, standard deviation, minimum, maximum, median, 95th, and 99th percentile latencies.
- **Response Size Metrics:** Average, minimum, maximum, median, 95th, and 99th percentile response sizes.
- **Status Code Distribution:** A breakdown of the response status codes received.
- **Throughput:** Requests per second.
- **Total Duration:** Total execution time.

If the `--json-summary-file` option is provided, the summary will also be saved in JSON format.

**Example**

```bash
python3 caddytest.py --num-requests 1000 --threads 4 --delay 0  --behavior stealth --progress
Requests: 100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1000/1000 [00:00<00:00, 2136.16it/s]

--- Test Summary ---
Total Requests       : 1000
Passed               : 574 (57.40% success)
Errors               : 0 (0.00% error)
Avg Latency          : 0.002 seconds
Std Latency          : 0.001 seconds
Min Latency          : 0.001 seconds
Max Latency          : 0.008 seconds
Median Latency       : 0.002 seconds
P95 Latency          : 0.003 seconds
P99 Latency          : 0.004 seconds
Throughput           : 2070.09 requests/second

Avg Response Size    : 5 bytes
Min Response Size    : 0 bytes
Max Response Size    : 12 bytes
Median Response Size : 0 bytes
P95 Response Size    : 12 bytes
P99 Response Size    : 12 bytes

Status Code Distribution: {403: 614, 200: 386}
Total Duration       : 0.48 seconds
```

---

## Contributing

Contributions to improve the script are welcome! If you find a bug, have a feature request, or would like to submit a pull request, please follow these steps:

1. Fork the repository.
2. Create a new branch for your changes: `git checkout -b my-feature`.
3. Commit your changes with clear messages.
4. Push to your fork and submit a pull request.
5. Ensure your code follows the style and testing guidelines.

For any issues or suggestions, please open an issue in this repository.
