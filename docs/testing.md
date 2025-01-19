# 🧪 Testing

## Basic Testing

The included `test.sh` script sends a series of `curl` requests to test various attack scenarios:

```bash
./test.sh
 ```

## Load Testing

Use a tool like `ab` to perform load testing:

```bash
ab -n 1000 -c 100 http://localhost:8080/
```

## Security Testing Suite

The `test.py` script provides a comprehensive check to verify the effectiveness of the configured WAF rules.

*   Each test case will result in either a pass or a fail, based on the rules configured in the WAF.
*   The output log contains detailed results for each test case, along with a summary of all tests performed.
*   An overall percentage is reported at the end, and if the percentage is below 90%, it's recommended to review the output log for further analysis of the failing tests.
*   The security testing suite will test SQL Injection, XSS, Path Traversal, RCE, and much more. You can find a list of tested attacks in the `test.py` script.
*   To run the security testing suite:

```bash
python3 test.py
```
