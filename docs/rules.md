  # 📜 Rules Format (`rules.json`)

  Rules are defined in a JSON file as an array of objects. Each rule specifies how to match a pattern, what parts of the request to inspect, and what action to take when a match is found.

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
        }
  ]
  ```

  ## Rule Fields

  | Field         | Description                                                                                                                                | Example                                         |
  |---------------|--------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
  | `id`          | Unique identifier for the rule.                                                                                                            | `sql_injection_1`                               |
  | `phase`       | Processing phase (1: Request Headers, 2: Request Body, 3: Response Headers, 4: Response Body).                                              | `2`                                             |
  | `pattern`     | Regular expression to match malicious patterns. Use `(?i)` for case insensitive matching.                                                  | `(?i)(?:select|insert|update)`                 |
  | `targets`     | Array of request parts to inspect, which can be: `URI`, `ARGS`, `BODY`, `HEADERS`, `COOKIES`, `HEADERS:<header_name>`,  `RESPONSE_HEADERS`, `RESPONSE_BODY`, `RESPONSE_HEADERS:<header_name>`, or `COOKIES:<cookie_name>`.| `["ARGS", "BODY"]`                               |
  | `severity`    | Severity of the rule (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). Used only for logging and metric reporting.                                   | `CRITICAL`                                      |
  | `action`      | Action to take on match (`block` or `log`). If empty or invalid, defaults to `block`.                                                     | `block`                                         |
  | `score`       | Anomaly score to add when this rule matches.                                                                                                | `5`                                             |
  | `description` | A descriptive text for the rule.                                                                                                            | `Detect SQL injection`                          |
  ```
