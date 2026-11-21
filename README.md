# SentinelForge v5.0 — Atlassian Teamwork Graph Blast-Radius, Autonomous Rovo Remediation & Zero-Leak Shield

> **Atlassian Codegeist 2026 — "Build with Context" (`Runs on Atlassian` Eligible — 0 External Cloud Egress)**  
> **Team:** Vision Flow Group (MD SHIHABUDDIN, MD Rafiul Islam Shubho, MD Anisur Rahman, Sharmin)  
> **Live Forge App ID:** `ari:cloud:ecosystem::app/dfccfe85-2f0a-4c82-9c88-c1dcf76cd975` | **MCP Skill Contract:** [`ATLASSIAN_MCP_SKILL.md`](./ATLASSIAN_MCP_SKILL.md)

## Why SentinelForge v5.0 Solves "Build with Context"
A leaked credential or indirect LLM prompt injection inside a single Jira issue rarely stays isolated. Engineers copy runbooks into Confluence, reference credentials in CI tickets, and expose Rovo or MCP AI agents across the entire workspace.

**SentinelForge v5.0** upgrades passive ticket scanning into an **active, context-aware Atlassian Teamwork Graph security engine** running 100% natively on Atlassian Forge (`0` bytes external egress):

1. **Atlassian Teamwork Graph Cross-Product Blast-Radius Engine (`src/engine/teamworkGraphEngine.js`):** Queries live Jira JQL (`/rest/api/3/search/jql`) and Confluence CQL (`/wiki/rest/api/content/search`) using safe non-secret prefix tokens to trace which related Jira tickets, Confluence specs, linked repositories, and workspace users share the exposure—computing an organization-wide `ORG_CRITICAL` / `CROSS_PRODUCT` / `CONTAINED` blast-radius graph.
2. **Autonomous Rovo Agent Remediation (`4` Native Rovo Actions):** Beyond alerting, the Rovo Security Guardian executes `map-teamwork-graph-blast-radius` and `remediate-and-create-incident`—posting a sanitized containment comment (zero raw secret echo), automatically opening a prioritized Security Incident ticket in Jira, and sealing the remediation event in the cryptographic ledger.
3. **Executive Visual Risk Dashboard (`jira:globalPage` — `src/frontend/dashboard.jsx`):** A manager-ready Atlassian Forge UI Kit command page featuring organization-wide KPI cards, visual `ProgressBar` threat breakdowns (Prompt Injections, Secret Leaks, Mobile Privacy), live Teamwork Graph blast-radius nodes, 1-click Red-Team simulation & Auto-Remediation controls, and SHA-256 ledger verification.
4. **4-Layer Zero-Egress Detection + Tamper-Evident SHA-256 Ledger (`src/engine/sentinelEngine.js`):** Blocks indirect LLM prompt injections & zero-width Unicode smuggling, Atlassian/AWS/Stripe/GitHub/Luhn payment leaks, Android 8–17 & Apple iOS `Info.plist` privacy hazards, and seals every audit into an append-only `prevHash -> entryHash` Forge Storage chain.

## Atlassian Surfaces & 5-Tool MCP Gateway
- **Jira Global Executive Dashboard (`jira:globalPage` — `sentinelforge-executive-dashboard`)**
- **Jira Issue Panel (`jira:issuePanel`)** + **Confluence Content Byline (`confluence:contentBylineItem`)**
- **Rovo Security Guardian (`rovo:agent`)** with 4 Actions: `scan-content-security`, `map-teamwork-graph-blast-radius`, `remediate-and-create-incident`, `verify-audit-ledger`
- **Automated Jira Issue Trigger (`avi:jira:created:issue`, `avi:jira:updated:issue`)**
- **Standalone 5-Tool Atlassian MCP Gateway (`mcp-server/index.mjs`)** + [`ATLASSIAN_MCP_SKILL.md`](./ATLASSIAN_MCP_SKILL.md)

## Automated Cloud Verification
```bash
node --test tests/sentinel.test.mjs
node ./mcp-server/index.mjs
```

## License
MIT License — Vision Flow Group.
