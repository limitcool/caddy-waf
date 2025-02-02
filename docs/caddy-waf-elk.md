# caddy-waf observability with ELK stack

You can push debug.json log to an ELK stack to have better observability and gather caddy-waf logs from multiple caddy servers.

![#caddy-waf-elk](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/caddy-waf-elk.png?raw=true)

## Quick start

```
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk/
docker-compose up setup
docker-compose up -d
```

Install filebeat (in my case on OSX I did `brew install filebeat` but on Linux can be `apt install filebeat` (Debian/Ubuntu) or `apk add filebeat` (Alpine) and so.. then backup original filebeat.yml conf somewhere and crete a new 
 `filebeat.yml` configuration file with the following content. Replace `your-elk-stack-ip` with your own Elasticsearch ip address.

```
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /path/to/caddy-waf/debug.json
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: message

output.elasticsearch:
  hosts: ["your-elk-stack-ip:9200"]
  username: "elastic"           # Replace with your Elasticsearch username
  password: "changeme"          # Replace with your Elasticsearch password

```

Access to your ELK stack admin dashboard at http://your-elk-stack-ip:5601 with credentials elastic/changeme, you will find caddy-waf log at the Observability Logs Explorer.

