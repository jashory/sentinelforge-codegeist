#!/usr/bin/env node
/**
 * SentinelForge Atlassian-Compatible Local MCP Server (JSON-RPC 2.0 over stdio)
 * Enables AI coding agents & Atlassian MCP workflows to audit Jira tickets, Confluence specs,
 * and mobile manifests before pushing to team workspaces.
 */

import readline from 'node:readline';
import { auditEngineeringPayload } from '../src/engine/sentinelEngine.js';

const TOOLS = [
  {
    name: 'sentinel_audit_jira_payload',
    description: 'Audit a Jira ticket, PR description, or Confluence document for leaked Atlassian/AWS/GitHub tokens, payment cards, and dangerous Android permissions with 0 third-party cloud egress.',
    inputSchema: {
      type: 'object',
      properties: {
        issueKey: { type: 'string', description: 'Optional Jira issue key (e.g., SEC-104)' },
        content: { type: 'string', description: 'Raw ticket, spec, or manifest text' }
      },
      required: ['content']
    }
  },
  {
    name: 'sentinel_redact_before_confluence',
    description: 'Return a clean air-gapped version of sensitive engineering docs safe to publish in Confluence or pass to Rovo Agents.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Raw engineering document text' }
      },
      required: ['content']
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
      serverInfo: { name: 'sentinelforge-atlassian-mcp', version: '1.0.0' }
    });
  }
  if (method === 'notifications/initialized') return;
  if (method === 'tools/list') return reply(id, { tools: TOOLS });
  if (method === 'tools/call') {
    const name = params?.name;
    const args = params?.arguments || {};
    if (name === 'sentinel_audit_jira_payload' || name === 'sentinel_redact_before_confluence') {
      const result = auditEngineeringPayload(args.content || '');
      return reply(id, {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ issueKey: args.issueKey || null, ...result }, null, 2)
          }
        ]
      });
    }
    return fail(id, -32601, `Unknown tool: ${name}`);
  }
  if (id !== undefined) return fail(id, -32601, `Unsupported method: ${method}`);
}

const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (isMain) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    try {
      handle(JSON.parse(line));
    } catch {
      fail(null, -32700, 'Invalid JSON');
    }
  });
}
