# 📜 Rules

The WAF's behavior is governed by a set of rules defined in a JSON file (`rules.json`). These rules specify how to identify and respond to potentially malicious requests. The rules are structured as an array of JSON objects, where each object represents an individual rule. This format allows for flexible and configurable security policies.

Here's a detailed breakdown of the rules format, including example rules and descriptions of each field:

```json
[
    {
        "id": "wordpress-brute-force",
        "phase": 2,
        "pattern": "(?i)(?:wp-login\\.php|xmlrpc\\.php).*?(?:username=|pwd=)",
        "targets": ["URI", "ARGS"],
        "severity": "HIGH",
        "action": "block",
        "score": 8,
        "description": "Block brute force attempts targeting WordPress login and XML-RPC endpoints."
    },
    {
        "id": "sql-injection-header",
        "phase": 1,
        "pattern": "(?i)(?:select|insert|update|delete|union|drop|--|;)",
        "targets": ["HEADERS:X-Attack"],
        "severity": "CRITICAL",
        "action": "block",
        "score": 10,
        "description": "Detect and block SQL injection attempts in custom header."
    },
    {
      "id": "log4j-jndi",
      "phase": 2,
      "pattern": "(?i)\\$\\{jndi:(ldap|rmi|dns):\\/\\/.*\\}",
      "targets": ["BODY","ARGS","URI","HEADERS"],
      "severity": "CRITICAL",
      "action": "block",
      "score": 10,
      "description":"Detect Log4j vulnerability attempts"
    },
    {
      "id": "low-score-log",
      "phase": 2,
      "pattern": "(?i)suspicious-keyword",
      "targets": ["BODY"],
      "severity": "LOW",
      "action": "log",
      "score": 1,
      "description": "Example of a low score log rule"
    },
    {
      "id": "specific-header-rule",
      "phase": 1,
       "pattern": "(?i)attack-payload",
       "targets": ["HEADERS:User-Agent"],
       "severity": "MEDIUM",
       "action": "block",
       "score": 7,
       "description": "Example blocking based on a User-Agent header payload"
     },
     {
       "id": "cookie-check",
       "phase": 1,
       "pattern": "(?i)bad_cookie",
       "targets": ["COOKIES:sessionid"],
       "severity": "HIGH",
       "action":"block",
       "score": 9,
       "description":"Example of a rule that targets cookies"
     },
     {
      "id": "response-header-check",
      "phase": 3,
       "pattern": "(?i)sensitive-info",
       "targets": ["RESPONSE_HEADERS:X-Server-Version"],
       "severity": "MEDIUM",
       "action": "log",
       "score": 2,
       "description": "Example of a response header rule"
     }
]
```

## Rule Fields: A Detailed Explanation

Each rule object contains the following fields:

| Field         | Description                                                                                                                                | Example                                         |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| **`id`**        | **Unique Identifier:** This is a string that uniquely identifies the rule within the `rules.json` file. It is used for logging, metric reporting, and rule management. It should be descriptive and easy to understand. IDs must be unique across all rules.  |  `sql_injection_1`, `xss-filter-block`, `wordpress-login-attempt`                               |
| **`phase`**      | **Processing Phase:**  An integer indicating the phase of request/response processing in which this rule should be applied.  The phases are:  <br>   * `1`: *Request Headers* (applied *before* request body processing)  <br>   * `2`: *Request Body* (applied *after* request headers have been parsed).  <br>   * `3`: *Response Headers* (applied *before* response body is sent). <br> * `4`: *Response Body* (applied *after* response headers have been written). The phase determines *when* the rule is evaluated. |   `1`, `2`, `3`, `4`                     |
| **`pattern`**    | **Regular Expression:** A string containing a regular expression that defines the pattern to match against the defined `targets`. The pattern must be a valid regex understood by the configured engine. Case-insensitive matching can be achieved by starting the pattern with `(?i)`.  It is highly recommended to ensure the regex is performant.  | `(?i)(?:select|insert|update)`, `(?i)\d{3}-\d{2}-\d{4}`, `(?:[a-zA-Z0-9_.-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+)`                  |
| **`targets`**    | **Inspection Targets:** An array of strings that specifies the parts of the request or response to inspect for a match.  The possible targets are:   * `URI`: The full URI of the request.  * `ARGS`: The query string parameters (if any).  * `BODY`: The body of the request. * `HEADERS`: All request headers are checked.  * `COOKIES`: All request cookies. * `HEADERS:<header_name>`: Specifically checks the value of the given header name (e.g., `HEADERS:User-Agent`, `HEADERS:X-Forwarded-For`). Header names should be case-insensitive.  * `COOKIES:<cookie_name>`:  Specifically checks the value of the specified cookie (e.g., `COOKIES:sessionid`). Cookie names should be case-insensitive.  *  `RESPONSE_HEADERS`: All response headers are checked. * `RESPONSE_BODY`: The full response body.  * `RESPONSE_HEADERS:<header_name>`:  Specifically checks the value of the given response header. The header name is case-insensitive. The `targets` array determines *where* the rule looks for matches. | `["ARGS", "BODY"]`, `["HEADERS:X-Custom-Header"]`, `["URI"]`, `["COOKIES:sessionid"]`, `["RESPONSE_HEADERS:Content-Type"]`                               |
| **`severity`**   | **Severity Level:**  A string representing the severity of the rule violation (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). This is used for logging, metrics, and reporting, but does not directly impact the processing of the request, or if the rule is enabled or not. You can use these labels to prioritize analysis, filtering and alerting. | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`                                  |
| **`action`**     | **Action on Match:** A string specifying the action to take when a rule is matched. The currently supported actions are:    * `block`:  The request or response is blocked, and the processing of the request/response chain is terminated.   * `log`:  The rule match is logged, but the processing of the request/response continues normally. If this field is empty, or is set to any invalid value, it defaults to `block`. | `block`, `log`                                       |
| **`score`**     | **Anomaly Score:** An integer representing a numerical score added to an internal anomaly score counter when a rule matches. The score is used in conjunction with other rules to indicate the severity of the event. It is typically used to decide when an overall threshold has been reached. A higher score generally means a more severe attack. This score can be used for threshold-based blocking or other aggregation mechanisms in a broader system. | `5`, `10`, `1`, `3`                                         |
| **`description`**| **Rule Description:** A string providing a human-readable description of the rule. It should explain what the rule is designed to detect. This description is useful for rule management, audits, and troubleshooting.  | `Detect SQL injection attempts`, `Block access to admin pages`, `Detect XSS in request`                                |

### Key Considerations:

*   **Rule Order:** The order of rules in `rules.json` can sometimes be significant, particularly with respect to how the WAF operates with regards to short-circuiting the rule chain after a match. In some WAF implementations, when a rule with action `block` is matched then the request is blocked and no further rules are processed. In other implementations, even if a `block` action is triggered, the rules may continue to execute but the original response will not change.
*   **Regular Expression Performance:** Complex regular expressions can have a significant impact on WAF performance. Ensure the patterns are efficient and avoid complex backtracking if performance becomes an issue.
*   **False Positives:** Rules must be carefully crafted to minimize false positives. Thoroughly test and validate rules with a wide range of requests to ensure proper operation.
* **Testing:** It is important to have a thorough testing strategy which includes both positive (attacks) and negative testing to be able to ensure that there are no false positives and that rules work correctly.
*   **Rule Updates:** Regularly update rules based on new vulnerabilities and attack patterns.
*   **Data Validation:** Ensure that the JSON is valid and that all fields are correctly formatted as expected.
*  **Case sensitivity:** Regex patterns are case sensitive unless they are specifically marked as insensitive (e.g., `(?i)`). Header and cookie names in the `targets` field are not case sensitive.

By using the `rules.json` format correctly and understanding the meaning of each rule field, you can create a robust and effective WAF configuration that provides strong protection against a wide range of web application attacks. This structured format enables granular control over the rules, allowing administrators to fine-tune the system for their specific environment and security needs.
