---
name: fofamap
description: Use FofaMap to validate FOFA syntax, search and profile internet assets, aggregate statistics, export bounded results, and manage authorized scan plans through its MCP tools. Trigger for FOFA queries, external attack-surface discovery, host intelligence, favicon searches, asset inventory, exposure analysis, or FOFA result exports.
---

# FofaMap

Use the FofaMap MCP server for evidence-based FOFA asset research. Prefer the MCP tools over shell commands when they are available.

## Workflow

1. Clarify the target, ownership or authorization boundary, desired fields, time range, and result limit when these materially affect the request. Call `fofa_account` and `fofa_fields` when membership-dependent capabilities matter; these tools work even in hosts that do not expose MCP Resources.
2. If the user names a product, OA, VPN, middleware, database, camera, CMS, or ops panel, call `fofa_rules` **before** `fofa_search`. Use the returned `query` values verbatim. Do not invent `app=` names. An empty keyword lists the bundled catalog (no FOFA quota).
3. Call `fofa_validate_query` before spending FOFA quota. Repair invalid syntax before searching.
4. Call `fofa_search` for the first bounded page. Use the smallest useful field set and size.
5. Use `fofa_search_next` only when more records are needed, passing its opaque cursor unchanged.
6. Use `fofa_host_profile` only when `fofa_account` shows Host aggregation (not registered users). Use `fofa_stats` only when the account has the stats API (professional / business / enterprise). Personal, ordinary, and education accounts should use `fofa_search` instead of stats.
7. Use `fofa_export` for large or reusable result sets, then poll `fofa_job_status`. Return the artifact path instead of pasting large tables.
8. Use `fofa_icon_search` for an explicit public website favicon. Prefer `fofa_agent_run` for open-ended Chinese/English discovery intents; for organization website discovery, return its structured `website_candidates` first, preserving `corroborated`, `observed`, and `candidate` status instead of flattening them into confirmed ownership.
9. State that FOFA observations and even cross-consistent title/certificate/ICP clues indicate exposed or corroborated candidates, not legal ownership or vulnerability, unless separately verified.

## Safety

- Treat searches, profiles, and statistics as passive intelligence collection, but still respect the user's scope and applicable rules.
- Never call `nuclei_plan` unless the user explicitly asks for active scanning and identifies an authorized scope.
- Review every target, template, and severity in the plan before asking for approval.
- Call `nuclei_execute` only after explicit approval for that exact plan. Never broaden or reuse an approval token.
- Do not interpret authentication, quota, timeout, or provider errors as an empty FOFA result.
- Never place `FOFA_API_KEY`, provider keys, bearer tokens, or approval tokens in reports or committed files.

## Host Fallback

If the host cannot expose MCP tools, use FofaMap's machine-readable CLI only for passive operations, for example `fofamap -q 'domain="example.com"' --output-format json --no-save` or `fofamap --rule 致远OA --output-format json --no-save`. Do not use the CLI to bypass host approval controls.

Read [references/tool-catalog.md](references/tool-catalog.md) when exact tool selection, pagination, resources, or host capability differences matter.
