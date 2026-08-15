# FofaMap tool catalog

## MCP tools

| Tool | Purpose | Side effect |
|---|---|---|
| `fofa_validate_query` | Validate FOFA syntax locally | None; no quota use |
| `fofa_fields` | Read field tiers and membership capability matrix | None; no quota use |
| `fofa_account` | Read current account tier, permissions and quota | FOFA quota/read |
| `fofa_search` | Fetch one structured result page | FOFA quota/read |
| `fofa_search_next` | Continue with an opaque cursor | FOFA quota/read |
| `fofa_icon_search` | Fetch a public favicon, calculate its FOFA hash and search it | Public HTTP + FOFA quota/read |
| `fofa_host_profile` | Load one host aggregation | FOFA quota/read; requires Host API membership |
| `fofa_stats` | Aggregate by supported dimensions | FOFA quota/read; requires stats API membership |
| `fofa_syntax` | Official query operators and fields | None |
| `fofa_rules` | Search bundled FOFA library `app=` names. Call **before** `fofa_search` when the user names a product/OA/VPN. Use returned queries verbatim. | None |
| `fofa_export` | Start a bounded background export | Writes a local artifact |
| `fofa_job_status` | Read export, agent, or scan job state | None |
| `fofa_agent_run` | Run the optional planning workflow without active scanning; organization website runs include evidence-labelled `website_candidates` | FOFA/model quota/read |
| `nuclei_plan` | Create an expiring, exact active-scan plan | Requires scanning enabled and authorization |
| `nuclei_execute` | Consume one approval token and execute the exact plan | Destructive/open-world |

## MCP resources

- `fofamap://fields`: versioned FOFA field catalogue and vip_level API matrix (`https://fofa.info/api`).
- `fofamap://rules`: bundled FOFA `app=` fingerprint library.
- `fofamap://account`: account capabilities and usage.
- `fofamap://jobs/{job_id}`: job metadata and artifact path.

DeepSeek Harness currently bridges MCP Tools only; MCP Resources and Prompts are unavailable there. Other hosts may expose resources through host-specific wrapper tools.

## Common query patterns

```text
domain="example.com"
cert="example.com"
app="nginx" && country="CN"
ip="192.0.2.1"
icon_hash="123456789"
```

For named products, do not guess `app=` strings. Call `fofa_rules` (for example keyword `致远OA` or `ThinkPHP`) and paste the returned query. `fofa_agent_run` does this lookup automatically.
