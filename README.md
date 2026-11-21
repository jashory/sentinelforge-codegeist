# SentinelForge MCP Guard v4.0 — 4-Layer Zero-Leak, Prompt-Injection & SHA-256 Ledger Shield for Atlassian

> **Atlassian Codegeist 2026 Submission (`Runs on Atlassian` Eligible — 0 External Cloud Egress)**  
> **Team:** Vision Flow Group (MD SHIHABUDDIN, md rafiul islam shubho, MD Anisur Rahman, Sharmin Kahnam)  
> **Live Forge App ID:** `ari:cloud:ecosystem::app/dfccfe85-2f0a-4c82-9c88-c1dcf76cd975` | **MCP Skill Contract:** [`ATLASSIAN_MCP_SKILL.md`](./ATLASSIAN_MCP_SKILL.md)

## Why SentinelForge v4.0 Matters
Enterprise Jira tickets and Confluence pages are now primary context feeds for AI agents (Atlassian Rovo, MCP coding assistants, autonomous workflows). That introduces two urgent risks:
1. **Indirect LLM Prompt Injection & Covert Markdown Exfiltration:** Attackers embed invisible zero-width Unicode strings or `![...](https://evil/?token=...)` beacons inside customer bug reports to hijack connected Rovo/MCP agents.
2. **Unchecked Secret & Mobile Privacy Leakage:** Engineers paste Atlassian `ATATT3x...` tokens, AWS/Stripe/Slack/GitHub keys, Luhn payment cards, and blanket Android 8–17 / Apple iOS camera-roll manifests directly into tickets.

## 4-Layer Zero-Egress Architecture (`0` External AI Bytes)
1. **Layer 1 — Indirect Prompt-Injection & Zero-Width Firewall (`src/engine/sentinelEngine.js`):** Quarantines system-prompt overrides, indirect exfiltration directives, zero-width Unicode smuggling (`U+200B..FEFF`), and Markdown image beacons before Rovo or external MCP agents ingest ticket text.
2. **Layer 2 — Enterprise Credential, Financial & Shannon-Entropy DLP:** Redacts Atlassian API tokens, AWS/Stripe/Slack/GitHub keys, private keys, Luhn payment cards, IBANs, NIDs/SSNs, JWTs, and high-entropy secrets (`H >= 4.25`).
3. **Layer 3 — Universal Mobile Privacy Forensics (Android 8–17 + Apple iOS `Info.plist`):** Audits `AndroidManifest.xml` (blanket camera-roll, ambient mic, SMS OTP) and Apple iOS `Info.plist` / `PrivacyInfo.xcprivacy` (`NSPhotoLibraryUsageDescription`, `NSAllowsArbitraryLoads` ATS cleartext downgrade, `NSPrivacyTracking`) directly inside engineering specs.
4. **Layer 4 — Tamper-Evident SHA-256 Hash-Chained Audit Ledger (Forge Storage):** Append-only `prevHash -> entryHash` cryptographic chain stored natively in Atlassian Forge Storage with 1-click tamper verification.

## Built-In 1-Click Judge Red-Team Replay Simulator
Open any Jira issue or Confluence page with SentinelForge installed and click any Red-Team replay button (`Fire Prompt Injection`, `Fire Cloud Key Leak`, `Fire Android/iOS Spec`, `Verify SHA-256 Ledger`) to watch live interception, quarantine, redaction, and SHA-256 chain sealing with **0 setup friction**.

## Atlassian Surfaces & 5-Tool MCP Gateway
- **Jira Issue Panel (`jira:issuePanel`)** + **Confluence Content Byline (`confluence:contentBylineItem`)**
- **Rovo Security Guardian (`rovo:agent`)** with Dual Actions (`scan-content-security` + `verify-audit-ledger`)
- **Automated Jira Issue Trigger (`avi:jira:created:issue`, `avi:jira:updated:issue`)**
- **Standalone 5-Tool Atlassian MCP Gateway (`mcp-server/index.mjs`)** + [`ATLASSIAN_MCP_SKILL.md`](./ATLASSIAN_MCP_SKILL.md)

## Automated Cloud Verification
```bash
node --test tests/sentinel.test.mjs
node ./mcp-server/index.mjs
```

## License
MIT License — Vision Flow Group.
