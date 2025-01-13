#!/usr/bin/env python3

import subprocess
import urllib.parse
import datetime
import argparse

# Configuration
TARGET_URL = 'http://localhost:8080'
TIMEOUT = 8
OUTPUT_FILE = "waf_test_results.log"
DEFAULT_USER_AGENT = "WAF-Test-Script/1.0" # Default User-Agent

# Colors for output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
YELLOW = '\033[0;33m'
NC = '\033[0m'

def test_url(url, description, expected_code, headers=None, body=None, default_user_agent=None):
    url_encoded = urllib.parse.quote(url, safe=':/?=&')
    curl_cmd = [
        'curl', '-s', '-k', '-w', '%{http_code}', '--connect-timeout', str(TIMEOUT),
        '--max-time', str(TIMEOUT), '-o', '/dev/null'
    ]

    if headers:
        headers_to_use = headers.copy()
        if 'User-Agent' not in headers_to_use and default_user_agent:
                headers_to_use['User-Agent'] = default_user_agent
    elif default_user_agent:
            headers_to_use = {'User-Agent': default_user_agent}
    else:
        headers_to_use = None



    if headers_to_use:
        for key, value in headers_to_use.items():
             curl_cmd.extend(['-H', f"{key}: {value}"])


    if body:
        curl_cmd.extend(['-d', body])

    curl_cmd.append(url_encoded)

    try:
        process = subprocess.run(curl_cmd, capture_output=True, text=True, check=False)
        response = process.stdout.strip()
        curl_status = process.returncode

        if curl_status != 0:
            print(f"{RED}[!]{NC} {description:<70} [CURL Error: {curl_status}]")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[ERROR] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, CURL Status: {curl_status}\n")
            return False

        if response == str(expected_code):
            print(f"{GREEN}[✓]{NC} {description:<70} [{response}]")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[PASS] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Got: {response}\n")
            return True
        else:
            print(f"{RED}[✗]{NC} {description:<70} [{response}] (Expected: {expected_code})")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[FAIL] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Got: {response}\n")
            return False

    except Exception as e:
        print(f"{RED}[!] {description:<70} [Exception: {e}]{NC}")
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"[ERROR] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Exception: {e}\n")
        return False

test_cases = [
    # SQL Injection (SQLi) Tests
    ("SQLi", f"{TARGET_URL}/?q=1", "SQLi (Level 1) - Basic Parameter", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'", "SQLi (Level 2) - Single Quote", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' -- -", "SQLi (Level 3) - Comment Injection", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' OR '1'='1", "SQLi (Level 4) - Simple OR Bypass", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND 1=1", "SQLi (Level 5) - Simple AND Bypass", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1; SELECT 1--", "SQLi (Level 6) - Statement Terminator", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=union select null,null--", "SQLi (Level 7) - Basic Union", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=union/*comment*/select null,null--", "SQLi (Level 8) - Union with Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=un/**/ion select null,null--", "SQLi (Level 9) - Union with Inline Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=%2575nion select null,null--", "SQLi (Level 10) - Union URL Encoded", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' ORDER BY 1--", "SQLi (Level 11) - Order By Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' GROUP BY 1--", "SQLi (Level 12) - Group By Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' HAVING 1=1--", "SQLi (Level 13) - Having Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1;EXEC xp_cmdshell 'dir'--", "SQLi (Level 14) - xp_cmdshell", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1;CREATE TABLE test (id INT)--", "SQLi (Level 15) - CREATE TABLE", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; INSERT INTO users (username) VALUES ('test')--", "SQLi (Level 16) - INSERT Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; UPDATE users SET username = 'test' WHERE id = 1--", "SQLi (Level 17) - UPDATE Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; DELETE FROM users WHERE id = 1--", "SQLi (Level 18) - DELETE Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND (SELECT COUNT(*) FROM users)=1--", "SQLi (Level 19) - Subquery", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND EXISTS (SELECT * FROM users)--", "SQLi (Level 20) - EXISTS Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND ASCII(SUBSTR((SELECT USER()),1,1))>1--", "SQLi (Level 21) - Blind SQL (ASCII)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND LENGTH((SELECT USER()))>1--", "SQLi (Level 22) - Blind SQL (Length)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1; IF (1=1) SELECT 1 ELSE SELECT 0;--", "SQLi (Level 23) - Conditional Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1--", "SQLi (Level 24) - Case Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 1) - Simple Header Injection", 403, {"X-Custom-SQL": "'"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 2) - Union in Header", 403, {"X-Custom-SQL": "union select 1,2--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 3) - Complex Union", 403, {"X-Custom-SQL": "/*!UNION*/ SELECT null, concat(0x7162717671,version(),0x716b717a71), null--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 1) - Simple Cookie Injection", 403, {"Cookie": "sql_injection='"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 2) - Basic Union", 403, {"Cookie": "sql_injection=union select 1,2--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 3) - Error Based", 403, {"Cookie": "sql_injection=1' AND (SELECT CHAR(75)||CHAR(97)||CHAR(122)||CHAR(99)||CHAR(75))>0--"}, None),
    
    # Cross-Site Scripting (XSS) Tests
    ("XSS", f"{TARGET_URL}/?x=test", "XSS (Level 1) - Plain Text", 200, None, None),
    ("XSS", f"{TARGET_URL}/?x=<script>alert(1)</script>", "XSS (Level 2) - Basic Script Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<img src=x onerror=alert(1)>", "XSS (Level 3) - IMG Onerror", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<img src=x οnerrοr=alert(1)>", "XSS (Level 4) - Obfuscated IMG Onerror", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=javascript:alert(1)", "XSS (Level 5) - JavaScript Protocol", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=JaVaScRiPt:alert(1)", "XSS (Level 6) - Mixed Case JavaScript Protocol", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=%3Cscript%3Ealert(1)%3C/script%3E", "XSS (Level 7) - URL Encoded Script", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=%253Cscript%253Ealert(1)%253C%252Fscript%253E", "XSS (Level 8) - Double URL Encoded", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<svg/onload=alert(1)>", "XSS (Level 9) - SVG Onload", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<svg onload='alert(1)'>", "XSS (Level 10) - SVG Onload with Quotes", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<a href=\"javascript:alert(1)\">Click</a>", "XSS (Level 11) - Anchor Tag JavaScript", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<a href=\"javascript:alert(1)\">Click</a>", "XSS (Level 12) - HTML Encoded JS", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=\"'><script>alert(1)</script>", "XSS (Level 13) - Attribute Breakout", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x='><script>alert(1)</script>", "XSS (Level 14) - Attribute Breakout (Single)", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<body onload=alert(1)>", "XSS (Level 15) - Body Onload", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<input onfocus=alert(1) autofocus>", "XSS (Level 16) - Input Onfocus Autofocus", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", "XSS (Level 17) - Iframe Srcdoc HTML Encoded", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<details open ontoggle=alert(1)>", "XSS (Level 18) - Details Ontoggle", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<%2Fscript><script>alert(1)</script>", "XSS (Level 19) - Breaking Script Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 1) - Basic Script in Header", 403, {"X-Custom-XSS": "<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 2) - URL Encoded Script", 403, {"X-Custom-XSS": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 1) - Basic Script", 403, {"Cookie": "xss=<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 2) - HTML Encoded Script", 403, {"Cookie": "xss=<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 1) - Basic Script", 403, None, "<script>alert(1)</script>"),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 2) - URL Encoded Script", 403, None, "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),

    # Remote Code Execution (RCE) Tests
    ("RCE", f"{TARGET_URL}/?cmd=whoami", "RCE (Level 1) - Simple Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=cat /etc/passwd", "RCE (Level 2) - Read File", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ls -la", "RCE (Level 3) - List Files", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=| whoami", "RCE (Level 4) - Pipe Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=; whoami", "RCE (Level 5) - Command Separator", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=%60whoami%60", "RCE (Level 6) - Backticks", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=echo \"test\"", "RCE (Level 7) - Quoted Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=uname -a", "RCE (Level 8) - System Information", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=id", "RCE (Level 9) - User ID", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=curl http://example.com", "RCE (Level 10) - Outbound Request", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=wget http://example.com", "RCE (Level 11) - Download File", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ping -c 1 example.com", "RCE (Level 12) - Network Utility", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=powershell.exe Get-Process", "RCE (Level 13) - PowerShell Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=python -c 'print(\"hello\")'", "RCE (Level 14) - Python Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=perl -e 'print \"hello\"'", "RCE (Level 15) - Perl Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 1) - Command in Header", 403, {"X-Custom-Cmd": "whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 2) - Command with Args", 403, {"X-Custom-Cmd": "cat /etc/passwd"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 1) - Command in Cookie", 403, {"Cookie": "rce_cmd=whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 2) - Command with Pipe", 403, {"Cookie": "rce_cmd=whoami | grep root"}, None),

    # Path Traversal Tests
    ("Path Traversal", f"{TARGET_URL}/file.txt", "Path Traversal (Level 1) - Direct File", 200, None, None),
    ("Path Traversal", f"{TARGET_URL}/../etc/passwd", "Path Traversal (Level 2) - Single Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../etc/passwd", "Path Traversal (Level 3) - Double Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../../etc/passwd", "Path Traversal (Level 4) - Triple Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../../../etc/passwd", "Path Traversal (Level 5) - Quadruple Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/....//etc/passwd", "Path Traversal (Level 6) - Obfuscated Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%2fetc%2fpasswd", "Path Traversal (Level 7) - URL Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%252fetc%252fpasswd", "Path Traversal (Level 8) - Double Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}//etc//passwd", "Path Traversal (Level 9) - Multiple Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/.../etc/passwd", "Path Traversal (Level 10) - Triple Dot Prefix", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..../etc/passwd", "Path Traversal (Level 11) - Quadruple Dot Prefix", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%c0%afetc%c0%afpasswd", "Path Traversal (Level 12) - UTF-8 Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/....%2fetc%2fpasswd", "Path Traversal (Level 13) - Mixed Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%2e%2f..%2e%2fetc%2fpasswd", "Path Traversal (Level 14) - Mixed Dot Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Header Level 1) - Referer Header", 403, {"Referer": "../../../etc/passwd"}, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 1) - Cookie Injection", 403, {"Cookie": "file=../../../etc/passwd"}, None),

    # Header Injection Tests
    ("Header", f"{TARGET_URL}/", "Header (Level 1) - Basic X-Forwarded-For", 403, {"X-Forwarded-For": "127.0.0.1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 2) - X-Forwarded-For with SQL", 403, {"X-Forwarded-For": "1' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 3) - X-Forwarded-For with XSS", 403, {"X-Forwarded-For": "<script>alert(1)</script>"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 4) - X-Forwarded-For Multiple IPs", 403, {"X-Forwarded-For": "127.0.0.1, example.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 5) - User-Agent SQL Injection", 403, {"User-Agent": "sqlmap/1.7-dev' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 6) - Referer Path Traversal", 403, {"Referer": "../../../etc/passwd"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 7) - Host Header Spoofing", 403, {"Host": "malicious.domain.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 8) - Accept-Language SQL", 403, {"Accept-Language": "en-US,sq' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 9) - Custom Header Injection", 403, {"X-Custom-Attack": "1; DROP TABLE users;"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 10) - Content-Type XSS", 403, {"Content-Type": "application/json; charset=<script>alert(1)</script>"}, None),

    # Protocol-Specific Tests
    ("Protocol", f"{TARGET_URL}/.git/HEAD", "Protocol (Level 1) - .git/HEAD", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.env", "Protocol (Level 2) - .env File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.htaccess", "Protocol (Level 3) - .htaccess", 403, None, None),
    ("Protocol", f"{TARGET_URL}//.git//HEAD", "Protocol (Level 4) - Obfuscated .git/HEAD", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.svn/entries", "Protocol (Level 5) - .svn/entries", 403, None, None),
    ("Protocol", f"{TARGET_URL}/WEB-INF/web.xml", "Protocol (Level 6) - WEB-INF/web.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/config.php.swp", "Protocol (Level 7) - config.php.swp", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.dockerenv", "Protocol (Level 8) - .dockerenv", 403, None, None),
    ("Protocol", f"{TARGET_URL}/server-status", "Protocol (Level 9) - Apache Server Status", 403, None, None),
    ("Protocol", f"{TARGET_URL}/robots.txt", "Protocol (Level 10) - robots.txt (Allowed)", 200, None, None),

    # Scanner Detection Tests
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 1) - SQLMap User-Agent", 403, {"User-Agent": "sqlmap/1.7-dev"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 2) - Acunetix User-Agent", 403, {"User-Agent": "acunetix-wvs"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 3) - Nikto User-Agent", 403, {"User-Agent": "Nikto/2.1.5"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 4) - Nmap User-Agent", 403, {"User-Agent": "Mozilla/5.0 Nmap"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 5) - Burp Suite User-Agent", 403, {"User-Agent": "Mozilla/5.0 (compatible; BurpSuite/2023.10.1)"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 6) - OWASP ZAP User-Agent", 403, {"User-Agent": "OWASP ZAP/2.12.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 7) - Nessus User-Agent", 403, {"User-Agent": "Nessus/10.7.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 8) - Qualys User-Agent", 403, {"User-Agent": "QualysAgent/1.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 9) - Wfuzz User-Agent", 403, {"User-Agent": "Wfuzz/2.4.2"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 10) - OpenVAS User-Agent", 403, {"User-Agent": "OpenVAS"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 11) - Skipfish User-Agent", 403, {"User-Agent": "Skipfish/2.16b"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 12) - Arachni User-Agent", 403, {"User-Agent": "Arachni/v2.4"}, None),

    # Insecure Deserialization Tests
    ("Insecure Deserialization", f"{TARGET_URL}/?data=rO0AB...", "Insecure Deserialization (Level 1) - Java Serialized", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/?data=YJv...base64...", "Insecure Deserialization (Level 2) - Python Pickle", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 1) - Serialized in Header", 403, {"X-Serialized-Data": "rO0AB..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 2) - Python Pickle in Header", 403, {"X-Serialized-Data": "YJv...base64..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 1) - Serialized in Cookie", 403, {"Cookie": "session=rO0AB..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 2) - JSON in Cookie", 403, {"Cookie": "session={\"type\":\"object\"...}"}, None),

    # Server-Side Request Forgery (SSRF) Tests
    ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1", "SSRF (Level 1) - Basic Internal Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=file:///etc/passwd", "SSRF (Level 2) - File Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://example.com", "SSRF (Level 3) - Outbound Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1:8080", "SSRF (Level 4) - Internal Request with Port", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=https://127.0.0.1", "SSRF (Level 5) - HTTPS Internal Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 1) - URL in Header", 403, {"X-Forwarded-Host": "http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 2) - Custom Header SSRF", 403, {"X-Custom-URL": "file:///etc/passwd"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 1) - URL in Cookie", 403, {"Cookie": "ssrf_url=http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 2) - File Protocol in Cookie", 403, {"Cookie": "ssrf_url=file:///etc/passwd"}, None),

    # XML External Entity (XXE) Injection Tests
    ("XXE", f"{TARGET_URL}/?xml=<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>", "XXE (Level 1) - Basic XXE", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<xml><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]><doc>&xxe;</doc></xml>", "XXE (Level 2) - External DTD", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"> <!ENTITY % eval \"<!ENTITY % exfil SYSTEM 'http://127.0.0.1/?data=%file;'>\">%eval;]><data>&exfil;</data>", "XXE (Level 3) - Parameter Entity", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % param1 SYSTEM \"file:///etc/passwd\">]><data>¶m1;</data>", "XXE (Level 4) - Parameter Entity", 403, None, None),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 1) - XML in Header", 403, {"Content-Type": "application/xml"}, "<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 2) - External Entity in Header", 403, {"Content-Type": "application/xml"}, "<xml><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]><doc>&xxe;</doc></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Body Level 1) - XML in Body", 403, None, "<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Body Level 2) - Parameter entity in Body", 403, None, "<xml><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"> <!ENTITY % eval \"<!ENTITY % exfil SYSTEM 'http://127.0.0.1/?data=%file;'>\">%eval;]><data>&exfil;</data></xml>"),

    # HTTP Request Smuggling
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 1) - CL.TE", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 2) - TE.CL", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 3) - CL-TE with Extra Headers", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Extra-Header":"test"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Header Level 1) - CL.TE in Header", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Custom-Data": "0\r\n\r\n"}, None),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Header Level 2) - TE.CL in Header", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Custom-Data": "0\r\n\r\n"}, None),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 1) - CL.TE in Body", 403, None, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 2) - TE.CL in Body", 403, None, "0\r\n\r\n"),

    # HTTP Response Splitting
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=X-Custom-Header: malicious\r\nContent-Type: text/html", "HTTP Response Splitting (Level 1) - Basic Header Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=X-Custom-Header: malicious%0d%0aContent-Type: text/html", "HTTP Response Splitting (Level 2) - CRLF Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 1) - Header Injection", 403, {"X-Custom-Header": "malicious\r\nContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 2) - Header with CRLF", 403, {"X-Custom-Header": "malicious%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 1) - Cookie Injection", 403, {"Cookie": "test=malicious\r\nContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 2) - Cookie with CRLF", 403, {"Cookie": "test=malicious%0d%0aContent-Type: text/html"}, None),

    # Insecure Direct Object References (IDOR)
    ("IDOR", f"{TARGET_URL}/user/1", "IDOR (Level 1) - Basic IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/2", "IDOR (Level 2) - Increment ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/abc", "IDOR (Level 3) - Non-Numeric ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/-1", "IDOR (Level 4) - Negative ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/0", "IDOR (Level 5) - Zero ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/1234567890", "IDOR (Level 6) - Large ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/..%2fetc%2fpasswd", "IDOR (Level 7) - Path Traversal in ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/admin/user/1", "IDOR (Level 8) - Different resource", 403, None, None),

    #Business Logic Vulnerabilities
    ("Business Logic", f"{TARGET_URL}/buy?item=1&quantity=1", "Business Logic (Level 1) - Basic Purchase", 403, None, None),
    ("Business Logic", f"{TARGET_URL}/buy?item=1&quantity=-1", "Business Logic (Level 2) - Negative Quantity", 403, None, None),
    ("Business Logic", f"{TARGET_URL}/transfer?from=user1&to=user2&amount=100", "Business Logic (Level 3) - Funds Transfer", 403, None, None),
    ("Business Logic", f"{TARGET_URL}/transfer?from=user1&to=user2&amount=-100", "Business Logic (Level 4) - Negative Transfer Amount", 403, None, None),
    ("Business Logic", f"{TARGET_URL}/?discount_code=DISCOUNT50", "Business Logic (Level 5) - Discount Code Abuse", 403, None, None),
    ("Business Logic", f"{TARGET_URL}/?promocode=TEST&price=1", "Business Logic (Level 6) - Price Manipulation", 403, None, None),

    # Clickjacking Tests
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 1) - Basic Iframe Test", 200, None, "<iframe src=\"{TARGET_URL}\"></iframe>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 2) - Double Iframe Test", 200, None, "<iframe src=\"{TARGET_URL}\"><iframe src=\"{TARGET_URL}\"></iframe></iframe>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 3) - Object Tag Test", 200, None, "<object data=\"{TARGET_URL}\"></object>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 4) - Embed Tag Test", 200, None, "<embed src=\"{TARGET_URL}\">"),

    # Cross-Site Request Forgery (CSRF) Tests
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 1) - Basic GET Request", 200, None, "<img src='{TARGET_URL}/transfer.php?amount=100&to=victim'>"),
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 2) - Basic POST Request", 200, None, '<form action="{TARGET_URL}/transfer.php" method="POST"><input type="hidden" name="amount" value="100"><input type="hidden" name="to" value="victim"><input type="submit" value="Transfer"></form>'),
    ("CSRF", f"{TARGET_URL}/change_email.php", "CSRF (Level 3) - POST with JSON", 200, {'Content-Type': 'application/json'}, '{"email": "attacker@example.com"}'),
    ("CSRF", f"{TARGET_URL}/change_password.php", "CSRF (Level 4) - Change Password", 200, None, '<form action="{TARGET_URL}/change_password.php" method="POST"><input type="hidden" name="old_password" value="current"><input type="hidden" name="new_password" value="new"><input type="submit" value="Change Password"></form>'),

    # Server-Side Template Injection (SSTI) Tests
    ("SSTI", f"{TARGET_URL}/?name={{7*7}}", "SSTI (Level 1) - Basic Math Expression", 200, None, None),
    ("SSTI", f"{TARGET_URL}/?name=${{7*7}}", "SSTI (Level 2) - Alternate Math Expression", 200, None, None),
    ("SSTI", f"{TARGET_URL}/?name=<% 7*7 %>", "SSTI (Level 3) - JSP-like Expression", 200, None, None),
    ("SSTI", f"{TARGET_URL}/?name={{config}}", "SSTI (Level 5) - Accessing Configuration", 200, None, None),
    ("SSTI", f"{TARGET_URL}/", "SSTI (Header Level 1) - Basic Expression in Header", 200, {"X-Custom-Name": "{{7*7}}"}, None),

    # Mass Assignment Tests
    ("Mass Assignment", f"{TARGET_URL}/profile/update", "Mass Assignment (Level 1) - Updating Admin Field", 200, {"Content-Type": "application/json"}, '{"isAdmin": true, "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/profile/update", "Mass Assignment (Level 2) - Updating Credit Limit", 200, {"Content-Type": "application/json"}, '{"creditLimit": 99999, "username": "test"}'),

    # NoSQL Injection Tests
    ("NoSQL Injection", f"{TARGET_URL}/?search[$gt]=null", "NoSQLi (Level 1) - MongoDB $gt Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$ne]=null", "NoSQLi (Level 2) - MongoDB $ne Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$regex]=.*", "NoSQLi (Level 3) - MongoDB $regex Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search=')", "NoSQLi (Level 4) - Basic String Injection", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 1) - Injection in Header", 403, {"X-Search-Param": "[$gt]=null"}, None),

    # XPath Injection Tests
    ("XPath Injection", f"{TARGET_URL}/?user=admin' or '1'='1", "XPath (Level 1) - Basic OR Bypass", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=admin' and '1'='2", "XPath (Level 2) - Basic AND Bypass", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[@name='admin']", "XPath (Level 3) - Direct Path Query", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 1) - Injection in Header", 403, {"X-User-Search": "' or '1'='1"}, None),

    # LDAP Injection Tests
    ("LDAP Injection", f"{TARGET_URL}/?user=*)((userPassword=*)", "LDAP (Level 1) - Basic Bypass", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/?user=admin)(&)", "LDAP (Level 2) - AND Injection", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/?user=*)(objectClass=*)", "LDAP (Level 3) - Retrieve All Objects", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 1) - Injection in Header", 403, {"X-User-Filter": "*)((userPassword=*)"}, None),

    # XML Injection (Other than XXE)
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>test</name></user>", "XMLi (Level 1) - Basic Structure", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name><![CDATA[<script>alert(1)</script>]]></name></user>", "XMLi (Level 2) - CDATA Injection", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 1) - XML in Header", 403, {"Content-Type": "application/xml"}, "<user><name>test</name></user>"),

    # File upload
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 1) - Malicious .php Upload", 403, None, "FAKE_PHP_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 2) - Double Extension .php.jpg", 403, None, "FAKE_IMAGE_CONTENT"),

    # JWT
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 1) - None Algorithm Attack", 403, {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicm9vdCJ9."}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 2) - HS256 with Public Key Confusion", 403, {"Authorization": "Bearer eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyIjoicm9vdCJ9.signature"}, None),

    # GraphQL Injection
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 1) - Basic Query Injection", 403, {"Content-Type": "application/json"}, '{"query":"{ user(id:1) { username, password } }"}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 2) - Injection via Variables", 403, {"Content-Type": "application/json"}, '{"query":"query getUser($id:Int){ user(id:$id){ username, password }}","variables":{"id":1}}'),

    # Valid Requests
    ("Valid", f"{TARGET_URL}/", "Valid (Level 1) - Homepage", 200, None, None),

]

def main():
    parser = argparse.ArgumentParser(description="WAF Security Test Suite")
    parser.add_argument("--user-agent", "-ua", type=str, default=DEFAULT_USER_AGENT,
                        help="Set a custom User-Agent string")

    args = parser.parse_args()
    custom_user_agent = args.user_agent
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("")  # Clear previous results

    print(f"{BLUE}WAF Security Test Suite{NC}")
    print(f"{BLUE}Target: {NC}{TARGET_URL}")
    print(f"{BLUE}Date: {NC}{datetime.datetime.now()}")
    print("----------------------------------------")

    total_tests = len(test_cases)
    passed = 0
    failed = 0

    for category, url, description, expected_code, headers, body in test_cases:
        if test_url(url, description, expected_code, headers, body, custom_user_agent):
            passed += 1
        else:
            failed += 1

    print("----------------------------------------")
    print(f"{BLUE}Results Summary{NC}")
    print(f"Total Tests: {total_tests}")
    print(f"{GREEN}Passed: {NC}{passed}")
    print(f"{RED}Failed: {NC}{failed}")

    if failed > 0:
        print(f"{RED}WAF Test Suite Failed: Please review {OUTPUT_FILE} for more details.{NC}")
    else:
        print(f"{GREEN}WAF Test Suite Passed! All checks are successful.{NC}")


if __name__ == "__main__":
    main()
