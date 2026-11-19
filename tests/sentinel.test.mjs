import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { auditEngineeringPayload } from '../src/engine/sentinelEngine.js';

const ROOT = path.resolve(import.meta.dirname, '..');

test('Atlassian Forge manifest.yml defines Jira, Confluence, Rovo Agent, Action, Trigger, and Node 22 runtime', () => {
  const manifest = fs.readFileSync(path.join(ROOT, 'manifest.yml'), 'utf8');
  assert.ok(manifest.includes('jira:issuePanel:'));
  assert.ok(manifest.includes('confluence:contentBylineItem:'));
  assert.ok(manifest.includes('rovo:agent:'));
  assert.ok(manifest.includes('scan-content-security'));
  assert.ok(manifest.includes('avi:jira:created:issue'));
  assert.ok(manifest.includes('nodejs22.x'));
});

test('SentinelForge engine detects Atlassian tokens, AWS keys, Luhn cards, and Android gallery harvesting chains', () => {
  const payload = `
    Ticket SEC-404:
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    CARD=4532-0151-1283-0366
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.INTERNET" />
  `;
  const report = auditEngineeringPayload(payload);
  assert.equal(report.thirdPartyCloudBytesSent, 0);
  assert.equal(report.verdict, 'BLOCK_AND_SANITIZE');
  assert.ok(report.riskScore >= 70);
  assert.ok(!report.redactedPayload.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(report.findings.some((f) => f.type === 'SILENT_CAMERA_ROLL_HARVESTING'));
});

test('Standalone Atlassian MCP server handles initialize, tools/list, and tools/call over JSON-RPC stdio', async () => {
  const child = spawn(process.execPath, [path.join(ROOT, 'mcp-server/index.mjs')], {
    stdio: ['pipe', 'pipe', 'pipe']
  });
  const replies = [];
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    for (const line of chunk.split('\n')) {
      if (line.trim()) replies.push(JSON.parse(line));
    }
  });
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) + '\n');
  child.stdin.write(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'sentinel_audit_jira_payload',
        arguments: { issueKey: 'SEC-99', content: 'Leaked key AKIAIOSFODNN7EXAMPLE' }
      }
    }) + '\n'
  );
  child.stdin.end();
  await new Promise((resolve) => child.on('close', resolve));
  assert.equal(replies.length, 3);
  assert.equal(replies[0].result.serverInfo.name, 'sentinelforge-atlassian-mcp');
  assert.equal(replies[1].result.tools.length, 2);
  const parsed = JSON.parse(replies[2].result.content[0].text);
  assert.equal(parsed.issueKey, 'SEC-99');
  assert.equal(parsed.totalFindings, 1);
  assert.equal(parsed.thirdPartyCloudBytesSent, 0);
});
