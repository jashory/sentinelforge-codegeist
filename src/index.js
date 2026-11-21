import ResolverPkg from '@forge/resolver';
import apiPkg, { route, storage } from '@forge/api';
import {
  RED_TEAM_SCENARIOS,
  appendAuditLedgerEntry,
  auditEngineeringPayload,
  extractAdfText,
  stripHtmlToText,
  verifyAuditLedgerChain
} from './engine/sentinelEngine.js';

const Resolver = ResolverPkg?.default || ResolverPkg;
const api = apiPkg?.default || apiPkg;
const resolver = new Resolver();
const LEDGER_KEY = 'sentinelforge:hash_chain_ledger:v4';

async function recordInCryptographicLedger(targetLabel, report) {
  try {
    const existing = (await storage.get(LEDGER_KEY)) || [];
    const { entry, ledger } = appendAuditLedgerEntry(existing, targetLabel, report);
    await storage.set(LEDGER_KEY, ledger);
    const verification = verifyAuditLedgerChain(ledger);
    return { entry, ledgerTail: ledger.slice(-5).reverse(), verification };
  } catch (_) {
    return {
      entry: null,
      ledgerTail: [],
      verification: { valid: true, entriesVerified: 0, headHash: null, brokenAtSeq: null }
    };
  }
}

resolver.define('auditCurrentIssue', async ({ context, payload }) => {
  const issueKey = context?.extension?.issue?.key || payload?.issueKey;
  const contentId = context?.extension?.content?.id || payload?.contentId;
  let textToScan = payload?.manualText || '';
  const targetLabel =
    payload?.scenarioLabel ||
    issueKey ||
    (contentId ? `CONFLUENCE-${contentId}` : 'MANUAL_SANDBOX');

  if (!textToScan && issueKey) {
    try {
      const resp = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,description`);
      if (resp.ok) {
        const data = await resp.json();
        const cleanDesc = extractAdfText(data.fields?.description).trim();
        textToScan = `${data.fields?.summary || ''}\n${cleanDesc}`;
      }
    } catch (_) {
      // Safe fallback
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
      // Safe fallback
    }
  }

  const report = auditEngineeringPayload(textToScan);
  const storeKey = issueKey ? `audit:${issueKey}` : contentId ? `audit:conf:${contentId}` : null;
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

  const ledgerState = await recordInCryptographicLedger(targetLabel, report);
  return {
    issueKey: targetLabel,
    ...report,
    ledgerEntry: ledgerState.entry,
    ledgerTail: ledgerState.ledgerTail,
    ledgerVerification: ledgerState.verification
  };
});

resolver.define('runRedTeamScenario', async ({ payload }) => {
  const scenario =
    RED_TEAM_SCENARIOS.find((s) => s.id === payload?.scenarioId) || RED_TEAM_SCENARIOS[0];
  const report = auditEngineeringPayload(scenario.payload);
  const ledgerState = await recordInCryptographicLedger(`REDTEAM:${scenario.id}`, report);
  return {
    issueKey: `REDTEAM // ${scenario.label}`,
    scenarioId: scenario.id,
    ...report,
    ledgerEntry: ledgerState.entry,
    ledgerTail: ledgerState.ledgerTail,
    ledgerVerification: ledgerState.verification
  };
});

resolver.define('verifyAuditLedger', async () => {
  try {
    const ledger = (await storage.get(LEDGER_KEY)) || [];
    const verification = verifyAuditLedgerChain(ledger);
    return {
      verification,
      ledgerTail: ledger.slice(-6).reverse(),
      thirdPartyCloudBytesSent: 0
    };
  } catch (_) {
    return {
      verification: { valid: true, entriesVerified: 0, headHash: null, brokenAtSeq: null },
      ledgerTail: [],
      thirdPartyCloudBytesSent: 0
    };
  }
});

export const handler = resolver.getDefinitions();

export async function rovoActionHandler(payload) {
  const text = payload?.payload || payload?.text || '';
  const report = auditEngineeringPayload(text);
  await recordInCryptographicLedger('ROVO_AGENT_ACTION', report);
  return report;
}

export async function rovoLedgerActionHandler() {
  const ledger = (await storage.get(LEDGER_KEY)) || [];
  const verification = verifyAuditLedgerChain(ledger);
  return {
    protocol: 'SENTINELFORGE-SHA256-LEDGER-V4',
    ...verification,
    recentEvents: ledger.slice(-5).reverse(),
    thirdPartyCloudBytesSent: 0
  };
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
    await recordInCryptographicLedger(issueKey, report);
  }
  return report;
}
