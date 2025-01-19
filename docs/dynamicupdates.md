# 🔄 Dynamic Updates

*   Most changes to the configuration (rules, blacklists, etc) can be applied without restarting Caddy.
*   File watchers monitor the changes on your rules and blacklist files and trigger the automatic reload.
*   Simply modify the related files and the changes will be applied automatically by the file watcher.
*   To reload configurations using the Caddy API execute `caddy reload`.

