#!/usr/bin/env node
/**
 * SentinelForge v4.0 Atlassian-Compatible Local MCP Security Gateway (JSON-RPC 2.0 over stdio)
 * Enables AI coding agents (Kiro, Claude, Rovo, Cursor) & Atlassian MCP workflows to neutralize
 * indirect prompt injections, scrub leaked Atlassian/AWS/Stripe/GitHub tokens, audit Android 8-17
 * & Apple iOS manifests, and verify SHA-256 hash-chained audit ledgers with 0 external egress.
 */

import readline from 'node:readline';
import {
  RED_TEAM_SCENARIOS,
  auditAndHealGitBundle,
  auditEngineeringPayload,
  verifyAuditLedgerChain
} from '../src/engine/sentinelEngine.js';

const TOOLS = [
  {
    name: 'sentinel_audit_jira_payload',
    description: '4-layer audit of a Jira ticket, PR description, or Confluence document for indirect LLM prompt injections, Atlassian/AWS/Stripe/GitHub tokens, Luhn cards, and Android 8-17 / iOS privacy risks (0 external egress).',
    inputSchema: {
      type: 'object',
      properties: {
        issueKey: { type: 'string', description: 'Optional Jira issue key (e.g., KAN-1)' },
        content: { type: 'string', description: 'Raw ticket, spec, AndroidManifest.xml, or iOS Info.plist text' }
      },
      required: ['content']
    }
  },
  {
    name: 'sentinel_redact_before_confluence',
    description: 'Return a sanitized, prompt-injection-quarantined version of sensitive engineering docs safe to publish in Confluence or pass to Rovo Agents.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Raw engineering document text' }
      },
      required: ['content']
    }
  },
  {
    name: 'sentinel_firewall_prompt_injection',
    description: 'Dedicated pre-LLM indirect prompt-injection & covert Markdown image exfiltration firewall for Atlassian MCP & Rovo agent pipelines.',
    inputSchema: {
      type: 'object',
      properties: {
        untrustedText: { type: 'string', description: 'Untrusted Jira comment, Confluence page, or ticket text before feeding to an LLM' }
      },
      required: ['untrustedText']
    }
  },
  {
    name: 'sentinel_verify_ledger_chain',
    description: 'Cryptographically verify an exported SentinelForge SHA-256 hash-chained audit ledger for zero tampering.',
    inputSchema: {
      type: 'object',
      properties: {
        ledger: { type: 'array', description: 'Array of SHA-256 chained audit ledger entries' }
      },
      required: ['ledger']
    }
  },
  {
    name: 'sentinel_run_red_team_benchmark',
    description: 'Execute all 4 built-in SentinelForge v5.1 Red-Team attack probes locally and return deterministic pass/fail telemetry.',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'sentinel_prepush_git_guard',
    description: 'Pre-commit / pre-push git bundle firewall and auto-healer: intercepts Google/Firebase (AIza...), OpenAI/Anthropic (sk-...), HuggingFace (hf_...), AWS, GitHub, Atlassian keys, and private-to-public SPA index.html overwrites before git push and returns auto-healed files.',
    inputSchema: {
      type: 'object',
      properties: {
        files: {
          type: 'object',
          description: 'Map of relative file paths to raw file contents staged for commit or push'
        },
        isPublicRepo: {
          type: 'boolean',
          description: 'Whether the target repository is public (defaults to true)'
        }
      },
      required: ['files']
    }
  }
];

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function fail(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}

function handle(msg) {
  const { id, method, params } = msg || {};
  if (method === 'initialize') {
    return reply(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'sentinelforge-atlassian-mcp', version: '4.0.0' }
    });
  }
  if (method === 'notifications/initialized') return;
  if (method === 'tools/list') return reply(id, { tools: TOOLS });
  if (method === 'tools/call') {
    const name = params?.name;
    const args = params?.arguments || {};
    let out;
    if (name === 'sentinel_audit_jira_payload' || name === 'sentinel_redact_before_confluence') {
      out = { issueKey: args.issueKey || null, ...auditEngineeringPayload(args.content || '') };
    } else if (name === 'sentinel_firewall_prompt_injection') {
      const full = auditEngineeringPayload(args.untrustedText || '');
      out = {
        safeForLlm: full.promptInjectionsBlocked === 0 && full.secretsBlocked === 0,
        promptInjectionsBlocked: full.promptInjectionsBlocked,
        secretsBlocked: full.secretsBlocked,
        verdict: full.verdict,
        sanitizedPromptContext: full.redactedPayload,
        payloadSha256: full.payloadSha256,
        thirdPartyCloudBytesSent: 0
      };
    } else if (name === 'sentinel_verify_ledger_chain') {
      out = { ...verifyAuditLedgerChain(args.ledger || []), thirdPartyCloudBytesSent: 0 };
    } else if (name === 'sentinel_run_red_team_benchmark') {
      out = {
        protocol: 'SENTINELFORGE-REDTEAM-V4',
        results: RED_TEAM_SCENARIOS.map((s) => {
          const r = auditEngineeringPayload(s.payload);
          return {
            id: s.id,
            label: s.label,
            verdict: r.verdict,
            riskScore: r.riskScore,
            totalFindings: r.totalFindings,
            promptInjectionsBlocked: r.promptInjectionsBlocked,
            secretsBlocked: r.secretsBlocked,
            mobileRisksBlocked: r.mobileRisksBlocked
          };
        }),
        thirdPartyCloudBytesSent: 0
      };
    } else if (name === 'sentinel_prepush_git_guard') {
      out = auditAndHealGitBundle(args.files || {}, {
        isPublicRepo: args.isPublicRepo !== false
      });
    } else {
      return fail(id, -32601, `Unknown tool: ${name}`);
    }
    return reply(id, {
      content: [{ type: 'text', text: JSON.stringify(out, null, 2) }]
    });
  }
  if (id !== undefined) return fail(id, -32601, `Unsupported method: ${method}`);
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      handle(JSON.parse(trimmed));
    } catch {
      fail(null, -32700, 'Invalid JSON');
    }
  });
}
