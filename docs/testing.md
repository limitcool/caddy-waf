# 🧪 Testing

The `test.py` script provides a comprehensive security testing suite designed to verify the effectiveness of the configured WAF rules. This script goes beyond basic checks and simulates a wide range of attack scenarios across various attack vectors. It provides detailed logging and a summary of the test results, allowing you to fine-tune your WAF rules and settings.

## Purpose

The primary purpose of the `test.py` script is to:

*   **Automated Security Checks:** Provide an automated way to test the WAF against a broad range of attack scenarios, ensuring consistent and repeatable testing.
*   **Rule Validation:** Verify the WAF rules are correctly configured and functioning as expected by simulating a wide range of attacks.
*   **Detailed Logging:** Generate detailed logs of each test case, including the request details, response codes, and whether each test passed or failed.
*   **Performance Tracking:** Track the number of passed and failed tests over time. This can be used to verify that changes in the WAF or its rules do not break expected behavior, which is a key indicator to ensure that the WAF is running well.
*   **Identify Weaknesses:** Help identify specific areas where the WAF might be weak or have misconfigured rules so that they can be fixed accordingly.

## Functionality

The `test.py` script works by:

1.  **Defining Test Cases:** Each test case consists of:
    *   A descriptive name (`description`).
    *   A target URL (`url`).
    *   An expected HTTP response code (`expected_code`).
    *   Optional headers (`headers`).
    *   Optional request body (`body`).
    *   Optional category name, to help in organizing the output
2.  **Sending Requests:** The script uses `curl` to send HTTP requests with the specified parameters.
3.  **Response Verification:** After sending a request, it checks the HTTP response code and determines if it matches the expected value.
4.  **Detailed Logging:** All test results are written to a log file (`waf_test_results.log`), including the test description, URL, headers, body, the expected code, and the actual response received. The log file is also categorized according to the test type.
5.  **Test Summary:** At the end of the test run, a summary is printed to the console, which includes:
    *   The total number of tests.
    *   The number of tests that passed.
    *   The number of tests that failed.
    *   A message indicating if the test suite passed, or failed, depending on the number of failures.
6.  **Color-Coded Output:** The output is color-coded to provide quick visual feedback.
    *   Green indicates a successful test.
    *   Red indicates a failed test or errors during the test.
    *   Blue indicates a general information or header of the test execution.
    *   Yellow indicates generic messages

## How to Run the Script

1.  **Ensure Python 3 is installed:** The script requires Python 3 to execute.
2.  **Run the script:**
    ```bash
    python3 test.py
    ```
3.  **Analyze the Output:**
    *   Review the console output for the overall test results.
    *   Examine the `waf_test_results.log` file for detailed information about each test case.

## Script Usage

```bash
python3 test.py --user-agent "My Custom User Agent"
```

*   **`--user-agent` or `-ua`:** An optional argument to set a custom User-Agent string for all the tests.

## Test Case Examples

The `test_cases` list contains a wide variety of tests, each designed to simulate a particular vulnerability or attack vector.

*   **SQL Injection:** Multiple levels of SQL injection attempts including basic syntax, comment bypasses, union injections, and more. It also tests SQL injection via HTTP headers and cookies.
*   **Cross-Site Scripting (XSS):** A large number of XSS attempts using script tags, image tags, event handlers, Javascript URLs, URL encoded and other obfuscated payloads. The tests include XSS payloads in GET parameters, cookies, headers and body.
*   **Remote Code Execution (RCE):** Tests for command injection using various techniques including `cmd` parameter, shell commands, backticks, and other common payloads used in RCE attacks. RCE is also tested via HTTP headers and Cookies.
*  **Path Traversal:** Tests multiple variations of path traversal by using double dots, triple dots, URL encoded path traversals, Unicode encoding, and other obfuscation techniques. Path traversal is also tested using headers and cookies.
*  **Header Injection:** Various header injection techniques are tested such as X-Forwarded-For injection, Host header manipulation, Content-Type injection, and more.
*  **Protocol Attacks:** Checks for exposure of configuration files, version control directories, and sensitive system files, using different path variations.
*  **Scanner Detection:** Simulates requests from various vulnerability scanners, to verify that those are properly blocked.
* **Insecure Deserialization:** Tests Java, Python, and PHP deserialization vulnerabilities by sending serialized data. It includes tests via URL parameters, headers and cookies.
*   **Server-Side Request Forgery (SSRF):** Simulates SSRF attacks by using a variety of protocols, IP addresses and techniques. SSRF is tested also via headers and cookies.
*   **XML External Entity (XXE):** Tests XXE vulnerabilities using both inline and external entities, with and without parameter entities. XXE is tested via URL parameters, headers and body.
*   **HTTP Request Smuggling:** Tests several HTTP request smuggling scenarios by using different header combinations, and checking how those are handled by the WAF. It includes tests via headers, body, and the main URL.
*   **HTTP Response Splitting:** Tests how the WAF prevents HTTP response splitting attacks via GET parameters, headers and cookies, using different techniques such as newlines and CRLF.
*  **Insecure Direct Object Reference (IDOR):** Tests several variations of IDOR attacks by using different paths, numeric and alphanumeric identifiers.
*   **Clickjacking:** Tests if the WAF properly blocks clickjacking attacks, by injecting an `iframe` and checking if the WAF prevents rendering of the tested page in a frame. It includes tests with `object`, `embed`, `form`, `base`, `iframe` tags.
* **Cross-Site Request Forgery (CSRF):** Checks if the WAF has proper protection against CSRF attacks, including via GET, POST, different content types, and various other parameters.
*   **Server-Side Template Injection (SSTI):** Tests how the WAF prevents SSTI attacks by sending expressions that should be evaluated by the template engine. SSTI is tested via URL parameters and headers.
*   **Mass Assignment:** Tests for mass assignment attacks via a variety of techniques, like sending JSON payload that attempts to modify protected attributes.
*   **NoSQL Injection:** Tests for common NoSQL injection payloads, specifically for MongoDB.
*   **XPath Injection:** Test the effectiveness of the XPath injection protection with different payloads, including wildcards and XPath functions.
* **LDAP Injection:** Tests a variety of LDAP payloads including bypasses, wildcards and common LDAP filters.
*   **XML Injection:** Tests for XML Injection vulnerabilities by sending malformed XML content and check if those are being properly filtered. This test is different from the XXE test as it tests other XML injection techniques.
*  **File Upload:** Tests file upload vulnerabilities by sending a variety of malicious file types, including PHP, shell scripts, images with PHP code, and more.
* **JWT Attacks:** Tests various JWT attack scenarios by modifying the JWT algorithm, header, payload, signature, and testing some well known exploits.
*  **GraphQL Injection:** Test the protection against GraphQL injection, by sending introspection queries, complex mutations, and other graphql attacks.
*   **Valid Requests:** Includes tests that should pass, to verify that the WAF does not introduce false positives and it is working correctly with valid requests.

## Best Practices

*   **Regular Testing:** Run the `test.py` script regularly, especially after modifying rules or blacklists.
*   **Custom Test Cases:**  Add new test cases to the `test_cases` list to test specific vulnerabilities or requirements that might be specific to your system.
*   **Review Logs:** Review the `waf_test_results.log` file to identify failed tests and understand what might be the issue.
*   **Customize Rules:** Adjust your WAF rules based on the test results to achieve the desired level of protection.
* **Dynamic Analysis:** In addition to running the automated test suite, perform manual security testing by interacting with your application and analyzing the behavior of the WAF in real time.
* **Integration with CI/CD:** Integrate the testing suite with your CI/CD pipelines to automate security testing as part of your software delivery process.
* **Real-World Scenarios:** Consider testing your rules against real-world attack scenarios using penetration testing tools.
* **Performance Testing:** The `test.py` script is not designed for performance testing, it is recommended to combine this test with load testing, using tools such as `ab` and others to ensure your WAF is performing correctly under high load.

## Conclusion

The `test.py` script is a comprehensive tool for security testing, allowing you to validate your WAF's effectiveness and identify potential vulnerabilities. By carefully analyzing the logs and output from this script, you can fine-tune your WAF configurations and rules, ensuring a high level of security for your web applications. Understanding how to interpret the results from this test suite is critical to guarantee that the WAF is working correctly and preventing potential attacks.
