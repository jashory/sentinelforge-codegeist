import ResolverPkg from '@forge/resolver';
import apiPkg, { route, storage } from '@forge/api';
import { auditEngineeringPayload, extractAdfText, stripHtmlToText } from './engine/sentinelEngine.js';

const Resolver = ResolverPkg?.default || ResolverPkg;
const api = apiPkg?.default || apiPkg;
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
        const cleanDesc = extractAdfText(data.fields?.description).trim();
        textToScan = `${data.fields?.summary || ''}\n${cleanDesc}`;
      }
    } catch (_) {
      // Fallback to empty/sandbox scan safely
    }
  } else if (!textToScan && contentId) {
    try {
      const resp = await api.asApp().requestConfluence(route`/wiki/api/v2/pages/${contentId}?body-format=storage`);
      if (resp.ok) {
        const data = await resp.json();
        const cleanBody = stripHtmlToText(data.body?.storage?.value || '');
        textToScan = `${data.title || ''}\n${cleanBody}`;
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
  const desc = extractAdfText(event?.issue?.fields?.description).trim();
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
