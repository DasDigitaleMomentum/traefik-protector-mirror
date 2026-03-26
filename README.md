# Protector Mirror — Traefik Middleware Plugin

Protector Mirror is a Traefik middleware plugin for edge-side security enforcement.
It fingerprints incoming requests, applies lightweight prefilter checks, enforces blocklists,
and asynchronously reports events to the Collector.

## Current capabilities

- Request fingerprinting from canonical headers
- Fingerprint blocklist enforcement (`/blocklist`)
- IP blocklist enforcement (`/ip-blocklist`)
- Dynamic prefilter config polling (`/prefilter-config`)
- Prefilter modes:
  - `detect`: log/observe prefilter hits, continue request
  - `enforce`: return `403` on prefilter match

## Dynamic config behavior

The plugin supports dynamic rule refresh from Collector for prefilter rules and keeps stale data on refresh errors.

- Blocklists refresh via `blocklistRefreshSec`
- Prefilter rules refresh via `prefilterRefreshSec`
- API key is forwarded as `X-API-Key` header (and `apiKey` query for blocklist/prefilter GET endpoints)

## Prefilter rules

Current prefilter schema:

- `uriLengthMax`
- `queryLengthMax`
- `queryParamCountMax`
- `headerValueLengthMax`
- `deniedPathPrefixes`
- `deniedUserAgentSubstrings`
- `deniedCountries` (Phase 3 placeholder)

### Geo-block placeholder (Phase 3)

`deniedCountries` is intentionally a data-model placeholder in Phase 3.

- Geo evaluation is **always skipped** in Phase 3.
- This is true even if a `GeoIPResolver` instance exists.
- The plugin logs: `GeoIP not available, skipping geo-block`.
- No country lookup or geo-based deny decision is executed in Phase 3.

## Example Traefik dynamic config

```yaml
http:
  middlewares:
    protector:
      plugin:
        protector-mirror:
          collectorURL: "http://collector:8081"
          blocklistRefreshSec: 5
          prefilterRefreshSec: 30
          apiKey: "your-api-key"
          prefilterEnabled: true
          prefilterMode: "detect"
          prefilterFailMode: "open"
```

## Main settings

| Parameter | Type | Default | Description |
|---|---|---|---|
| `collectorURL` | string | `http://collector:8081` | Collector base URL |
| `blocklistRefreshSec` | int | `5` | Blocklist/IP-blocklist refresh interval |
| `prefilterRefreshSec` | int | `30` | Prefilter config refresh interval |
| `apiKey` | string | `""` | Collector authentication key |
| `prefilterEnabled` | bool | `true` | Enable prefilter checks |
| `prefilterMode` | string | `detect` | `detect` or `enforce` |
| `prefilterFailMode` | string | `open` | `open` or `closed` on prefilter evaluation error |

## Requirements

- Traefik v3.x
- Protector backend (Collector + Redis)

## License

[Business Source License 1.1](LICENSE) — free to use for non-production purposes.  
Changes to [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) on 2030-03-23.
