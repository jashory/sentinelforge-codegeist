# SentinelForge MCP Guard — Zero-Leak Secret, Permission & Rovo Security Guardian

> **Atlassian Codegeist 2026 Submission** — Targeting **Apps for Software Teams (15,000 USD)**, **Best App with Atlassian MCP (1,500 USD)**, **Best Agents / Rovo (1,500 USD)**, and **First-300 Atlassian Developer Swag Pack**.  
> **Author:** HM Shihabuddin Jashory (`@jashory`)

## Overview
Engineering teams routinely paste production `.env` configs, Atlassian API tokens, AWS keys, payment logs, and mobile `AndroidManifest.xml` specs into Jira tickets and Confluence pages. **SentinelForge MCP Guard** runs deterministically inside **Atlassian Forge serverless Node.js 22 RAM** (`0` bytes sent to external third-party AI APIs) across **4 integrated surfaces**:

1. **Jira Issue Panel (`jira:issuePanel`)**: Scans the active Jira ticket and renders a zero-leak verdict, redacted safe payload, and instant sandbox scanner.
2. **Confluence Content Byline (`confluence:contentBylineItem`)**: Audits technical specs for leaked credentials and risky mobile permissions.
3. **Atlassian Rovo Security Agent (`rovo:agent` + `scan-content-security` Action)** + **Auto Jira Trigger (`avi:jira:created:issue` / `updated`)**: Continuously watches new/updated issues and empowers Rovo conversations to sanitize tickets automatically.
4. **Standalone Atlassian-Compatible MCP Server (`mcp-server/index.mjs`)**: Zero-dependency JSON-RPC 2.0 stdio MCP server exposing `sentinel_audit_jira_payload` and `sentinel_redact_before_confluence`.

## 3-Command Live Deployment (Atlassian Forge)
```bash
npm install -g @forge/cli
forge login
forge register && forge deploy && forge install
```

## Automated Cloud Verification
```bash
node --test tests/sentinel.test.mjs
```
