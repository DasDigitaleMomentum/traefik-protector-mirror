# Protector Mirror — Traefik Middleware Plugin

A lightweight Web Application Firewall (WAF) for [Traefik](https://traefik.io/) that sits in the request path, fingerprints every visitor, and enforces blocklists in real time.

Built for hybrid detection — rule-based analysis today, AI-powered classification on the roadmap.

> ⚠️ **Early access.** Protector Mirror is under active development. A public release with full documentation will follow here. Until then, this plugin is designed to work with the Protector backend stack and is not standalone.

---

## What it does

This Traefik middleware intercepts incoming HTTP requests and:

1. **Computes a browser fingerprint** from a canonical set of request headers
2. **Checks fingerprint and IP blocklists** with automatic background refresh
3. **Blocks known bad actors** immediately (returns `403 Forbidden`)
4. **Forwards request events** asynchronously to the Collector for analysis

All of this happens at the edge — before your application sees the request.

## Configuration

```yaml
# Traefik dynamic configuration
http:
  middlewares:
    protector:
      plugin:
        protector-mirror:
          collectorURL: "http://collector:8081"
          blocklistRefreshSec: 5
          apiKey: "your-api-key"
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `collectorURL` | string | `http://collector:8081` | Collector service endpoint |
| `blocklistRefreshSec` | int | `5` | Blocklist polling interval in seconds |
| `apiKey` | string | `""` | API key for Collector authentication |

## How it works

The plugin runs as Traefik middleware — no sidecar, no external process. Blocklists are cached in memory and refreshed on a configurable interval. Event dispatch to the Collector is non-blocking (buffered channel with async workers), so request latency stays minimal.

Fingerprints are deterministic: same headers, same fingerprint. The Collector aggregates these signals, and the Probe service evaluates rules to decide who gets blocked.

## Requirements

- Traefik v3.x
- A running Protector backend (Collector + Redis, at minimum)

## Stack

Protector Mirror is one piece of a larger system:

- **This plugin** — request interception at the Traefik edge
- **Collector** — event ingestion, fingerprint storage, blocklist management
- **Probe** — rule engine for automated threat evaluation
- **Dashboard** — real-time monitoring UI with WebSocket live feed

Full stack documentation will be published when the project goes public.

## License

[Business Source License 1.1](LICENSE) — free to use for non-production purposes.  
Changes to [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) on 2030-03-23.

Copyright © 2026 DasDigitaleMomentum
