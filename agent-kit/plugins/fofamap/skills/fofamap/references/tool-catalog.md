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
| `fofa_rules` | Search bundled FOFA library `app=` names | None |
| `fofa_export` | Start a bounded background export | Writes a local artifact |
| `fofa_job_status` | Read export, agent, or scan job state | None |
| `fofa_agent_run` | Run planning and return evidence-labelled website candidates when relevant | FOFA/model quota/read |
| `nuclei_plan` | Create an expiring, exact active-scan plan | Requires scanning enabled and authorization |
| `nuclei_execute` | Consume one approval token and execute the exact plan | Destructive/open-world |

MCP Resources mirror fields, rules, account, and jobs for hosts that expose Resources. Tools-only hosts should use `fofa_fields`, `fofa_account`, `fofa_rules`, and `fofa_job_status`.
