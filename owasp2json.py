import requests
import re
import json
import time

def download_owasp_rules(repo_url, rules_dir, output_path):
    all_rules = []
    headers = {}
    
    try:
        api_url = f"https://api.github.com/repos/{repo_url}/contents/{rules_dir}"
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        
        for file in response.json():
            if not file['name'].endswith('.conf'):
                continue
                
            time.sleep(1)
            response = requests.get(file["download_url"], headers=headers)
            print(f"Processing rule file: {file['name']}")
            
            rules = extract_rules(response.text)
            all_rules.extend(rules)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return

    with open(output_path, 'w') as f:
        json.dump(all_rules, f, indent=2)
    
    print(f"Saved {len(all_rules)} rules to {output_path}")

def extract_rules(rule_text):
    rules = []
    rule_pattern = r'SecRule\s+([^"]*)"([^"]+)"\s*(\\\s*\n\s*.*?|.*?)(?=\s*SecRule|\s*$)'
    
    for match in re.finditer(rule_pattern, rule_text, re.MULTILINE | re.DOTALL):
        try:
            variables, pattern, actions = match.groups()
            
            rule_id = re.search(r'id:(\d+)', actions)
            severity = re.search(r'severity:\'?([^,\'\s]+)', actions)
            action = re.search(r'action:\'?([^,\'\s]+)', actions)
            phase = re.search(r'phase:(\d+)', actions)
            
            if not rule_id:
                continue
            
            # Escape special regex characters in pattern
            pattern = pattern.replace('[CDATA[', '\\[CDATA\\[')
            
            # Validate regex pattern
            try:
                re.compile(pattern)
            except re.error:
                print(f"Invalid regex pattern in rule {rule_id.group(1)}: {pattern}")
                continue
            
            targets = []
            if variables:
                for target in ["ARGS", "BODY", "URL", "HEADERS", "REQUEST_HEADERS",
                             "RESPONSE_HEADERS", "REQUEST_COOKIES", "USER_AGENT",  
                             "CONTENT_TYPE", "X-FORWARDED-FOR", "X-REAL-IP"]:
                    if target in variables.upper():
                        targets.append(target)
            
            severity_val = severity.group(1) if severity else "LOW"
            action_val = action.group(1) if action else "log"
            
            score = 5 if action_val == "block" else \
                   4 if severity_val.upper() == "HIGH" else \
                   3 if severity_val.upper() == "MEDIUM" else 1
            
            rule = {
                "id": rule_id.group(1),
                "phase": int(phase.group(1)) if phase else 2,
                "pattern": pattern,
                "targets": targets,
                "severity": severity_val,
                "action": action_val,
                "score": score
            }
            
            rules.append(rule)
            
        except (AttributeError, ValueError) as e:
            continue
            
    return rules

if __name__ == "__main__":
    repo_url = "coreruleset/coreruleset"
    rules_dir = "rules"
    output_path = "rules.json"
    
    download_owasp_rules(repo_url, rules_dir, output_path)
