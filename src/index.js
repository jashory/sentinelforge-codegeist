import Resolver from '@forge/resolver';
import api, { route, storage } from '@forge/api';
import { auditEngineeringPayload } from './engine/sentinelEngine.js';

const resolver = new Resolver();

resolver.define('auditCurrentIssue', async ({ context, payload }) => {
  const issueKey = context?.extension?.issue?.key || payload?.issueKey;
  let textToScan = payload?.manualText || '';

  if (!textToScan && issueKey) {
    const resp = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,description`);
    if (resp.ok) {
      const data = await resp.json();
      textToScan = `${data.fields?.summary || ''}\n${JSON.stringify(data.fields?.description || '')}`;
    }
  }

  const report = auditEngineeringPayload(textToScan);
  if (issueKey) {
    await storage.set(`audit:${issueKey}`, {
      auditedAt: new Date().toISOString(),
      riskScore: report.riskScore,
      verdict: report.verdict,
      totalFindings: report.totalFindings
    });
  }
  return { issueKey: issueKey || 'MANUAL_SANDBOX', ...report };
});

export const handler = resolver.getDefinitions();

export async function rovoActionHandler(payload) {
  const text = payload?.payload || payload?.text || '';
  return auditEngineeringPayload(text);
}

export async function issueTriggerHandler(event) {
  const issueKey = event?.issue?.key;
  const summary = event?.issue?.fields?.summary || '';
  const desc = JSON.stringify(event?.issue?.fields?.description || '');
  const report = auditEngineeringPayload(`${summary}\n${desc}`);
  if (issueKey) {
    await storage.set(`audit:${issueKey}`, {
      auditedAt: new Date().toISOString(),
      riskScore: report.riskScore,
      verdict: report.verdict,
      totalFindings: report.totalFindings
    });
  }
  return report;
}
