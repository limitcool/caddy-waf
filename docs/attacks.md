# 🛡️ Protected Attack Types

1.  **SQL Injection (SQLi):** Detects and blocks attempts to inject malicious SQL code.
2.  **Cross-Site Scripting (XSS):** Protects against the injection of malicious scripts into web pages.
3.  **Path Traversal:** Blocks access to restricted files and directories through directory traversal techniques.
4.  **Remote Code Execution (RCE):** Detects and prevents attempts to execute arbitrary commands on the server.
5.  **Log4j Exploits:** Identifies and blocks Log4j vulnerability related attack patterns.
6.  **Protocol Attacks:** Protects against attacks targeting sensitive protocol or configuration files.
7.  **Scanner Detection:** Detects and blocks requests originating from known vulnerability scanners.
8.  **Header & Cookie Injection:** Detects and blocks malicious content injected via headers and cookies.
9.  **Insecure Deserialization:** Blocks requests with potentially malicious serialized data.
10. **HTTP Request Smuggling:** Prevents attacks that bypass security devices using inconsistent header combinations.
11. **HTTP Response Splitting:** Blocks attempts to inject malicious code through header manipulation.
12. **Insecure Direct Object Reference (IDOR):** Detects attempts to access resources using predictable object IDs.
13. **Server-Side Request Forgery (SSRF):** Prevents attacks that make the server perform unauthorized requests.
14. **XML External Entity (XXE) Injection:** Blocks attacks leveraging XML external entity processing.
15. **Server-Side Template Injection (SSTI):** Prevents code injection through template engines.
16. **Mass Assignment:** Blocks unauthorized modification of object attributes through uncontrolled input.
17. **NoSQL Injection:** Prevents malicious NoSQL queries designed to bypass authentication or steal data.
18.  **XPath Injection:** Blocks attempts to manipulate XML documents with malicious XPath queries.
19. **LDAP Injection:** Detects and prevents the injection of malicious data into LDAP queries.
20. **XML Injection:** Detects various attacks exploiting XML manipulation.
21. **File Upload:** Blocks malicious file uploads to prevent execution of unwanted code.
22. **JWT Attacks:** Detects JWT tampering attempts and bypasses.
23. **GraphQL Injection:** Blocks attempts to perform unauthorized operations or extract data via GraphQL queries.
24. **Clickjacking:** Mitigates clickjacking attempts by preventing rendering the protected content inside a frame.
25.  **Cross-Site Request Forgery (CSRF):** Blocks CSRF attacks by preventing unauthorized requests from being performed.
