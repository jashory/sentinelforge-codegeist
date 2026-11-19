import Resolver from '@forge/resolver';
import api, { route, storage } from '@forge/api';
import { auditEngineeringPayload } from './engine/sentinelEngine.js';

const resolver = new Resolver();

resolver.define('auditCurrentIssue', async ({ context, payload }) => {
  const issueKey = context?.extension?.issue?.key || payload?.issueKey;
  const contentId = context?.extension?.content?.id || payload?.contentId;
  let textToScan = payload?.manualText || '';
  let targetLabel = issueKey || (contentId ? `CONFLUENCE-${contentId}` : 'MANUAL_SANDBOX');

  if (!textToScan && issueKey) {
    try {
      const resp = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,description`);
      if (resp.ok) {
        const data = await resp.json();
        textToScan = `${data.fields?.summary || ''}\n${JSON.stringify(data.fields?.description || '')}`;
      }
    } catch (_) {
      // Fallback to empty/sandbox scan safely
    }
  } else if (!textToScan && contentId) {
    try {
      const resp = await api.asApp().requestConfluence(route`/wiki/api/v2/pages/${contentId}?body-format=storage`);
      if (resp.ok) {
        const data = await resp.json();
        textToScan = `${data.title || ''}\n${data.body?.storage?.value || ''}`;
      }
    } catch (_) {
      // Fallback to empty/sandbox scan safely
    }
  }

  const report = auditEngineeringPayload(textToScan);
  const storeKey = issueKey ? `audit:${issueKey}` : (contentId ? `audit:conf:${contentId}` : null);
  if (storeKey) {
    try {
      await storage.set(storeKey, {
        auditedAt: new Date().toISOString(),
        riskScore: report.riskScore,
        verdict: report.verdict,
        totalFindings: report.totalFindings
      });
    } catch (_) {}
  }
  return { issueKey: targetLabel, ...report };
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
