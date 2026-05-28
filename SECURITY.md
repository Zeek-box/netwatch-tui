# Security

Netwatch TUI uses `sudo` only to read socket ownership through `ss -tunap`.

AbuseIPDB checks are manual lookups. The tool does not report IPs.

Stored API keys live in:

```text
~/.config/netwatch-tui/config.json
```

The config file is written with user-only permissions. Lookup logs are local and ignored by Git by default.

Incident-response captures are written under `captures/` and are ignored by Git by default. They may contain process paths, command lines, and network endpoints. Environment variables are not captured.
