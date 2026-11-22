/**
 * SentinelForge v5.0 — Atlassian Teamwork Graph Cross-Product Blast-Radius & Autonomous Remediation Engine
 * Correlates leaked credentials, indirect prompt injections, and mobile privacy risks across
 * Jira Issues, Confluence Pages, Bitbucket/Repo references, and Workspace Users strictly inside
 * Atlassian Forge serverless RAM (0 bytes external egress).
 */

export const TEAMWORK_GRAPH_DEMO_CONTEXT = {
  originIssue: {
    key: 'KAN-1',
    summary: 'Mobile Release v2.4 Auth & Camera-Roll Telemetry Hotfix',
    project: 'KAN',
    reporter: 'HM Shihabuddin Jashory',
    watchers: ['HM Shihabuddin Jashory', 'MD Rafiul Islam Shubho', 'Security Operations Lead']
  },
  relatedJiraIssues: [
    {
      key: 'KAN-4',
      summary: 'Staging CI Pipeline Runner Environment Variables',
      status: 'In Progress',
      assignee: 'Platform Engineer',
      matchedFingerprint: 'AWS_ACCESS_KEY (AKIA...MPLE)',
      accessScope: 'Project Members (12 users)'
    },
    {
      key: 'SEC-19',
      summary: 'Q4 API Key Rotation & Rovo Agent Prompt Hardening',
      status: 'Open',
      assignee: 'Security Operations Lead',
      matchedFingerprint: 'PROMPT_INJECTION_OVERRIDE',
      accessScope: 'Security & Engineering (18 users)'
    }
  ],
  relatedConfluencePages: [
    {
      id: '65793',
      title: 'Mobile Release Architecture & Android/iOS Permissions Spec',
      space: 'ENG',
      lastEditor: 'MD Rafiul Islam Shubho',
      matchedFingerprint: 'SILENT_CAMERA_ROLL_HARVESTING + AWS_ACCESS_KEY',
      accessScope: 'All Workspace Members (42 users)'
    },
    {
      id: '65812',
      title: 'Production Incident Runbook & Payment Gateway Debug Guide',
      space: 'OPS',
      lastEditor: 'Release Engineer',
      matchedFingerprint: 'HIGH_ENTROPY_CREDENTIAL',
      accessScope: 'Engineering & Support (31 users)'
    }
  ],
  linkedRepositories: [
    {
      name: 'visionflow/mobile-android-ios-client',
      branch: 'release/2.4',
      exposureSignal: 'AndroidManifest.xml & Info.plist spec mirror'
    }
  ]
};

/**
 * Extract safe search tokens (never full raw secrets!) from findings to query Jira JQL & Confluence CQL.
 */
export function extractSafeGraphQueryTerms(auditReport) {
  const terms = new Set();
  for (const f of auditReport?.findings || []) {
    if (f.category === 'SECRET_LEAK' || f.category === 'SECRET_DLP') {
      if (f.type.includes('AWS')) terms.add('AKIA');
      else if (f.type.includes('GOOGLE') || f.type.includes('FIREBASE')) terms.add('AIza');
      else if (f.type.includes('OPENAI') || f.type.includes('ANTHROPIC')) terms.add('sk-');
      else if (f.type.includes('HUGGINGFACE')) terms.add('hf_');
      else if (f.type.includes('GITHUB')) terms.add('ghp_');
      else if (f.type.includes('ATLASSIAN')) terms.add('ATATT');
      else if (f.type.includes('STRIPE')) terms.add('sk_live');
      else terms.add('API_KEY');
    } else if (f.category === 'PROMPT_INJECTION') {
      terms.add('ignore previous instructions');
    } else if (f.category === 'PERMISSION_CHAIN' || f.category === 'IOS_PRIVACY_CHAIN' || f.category === 'MOBILE_PRIVACY') {
      terms.add('READ_MEDIA_IMAGES');
    }
  }
  return Array.from(terms).slice(0, 4);
}

/**
 * Build a unified Atlassian Teamwork Graph blast-radius model from live Forge Jira/Confluence search results
 * (falling back cleanly to deterministic enterprise graph nodes when running in sandbox/demo mode).
 */
export function buildTeamworkGraphBlastRadius({
  originKey = 'KAN-1',
  auditReport,
  liveJiraHits = [],
  liveConfluenceHits = [],
  useSandboxFallback = false
}) {
  const nodes = [
    {
      id: `origin:${originKey}`,
      kind: 'JIRA_ISSUE',
      label: originKey,
      role: 'Origin Leak Source',
      severity: auditReport?.riskScore >= 70 ? 'CRITICAL' : auditReport?.riskScore >= 35 ? 'HIGH' : 'LOW'
    }
  ];
  const edges = [];

  const jiraHits =
    liveJiraHits.length > 0
      ? liveJiraHits
      : useSandboxFallback
        ? TEAMWORK_GRAPH_DEMO_CONTEXT.relatedJiraIssues
        : [];

  const confHits =
    liveConfluenceHits.length > 0
      ? liveConfluenceHits
      : useSandboxFallback
        ? TEAMWORK_GRAPH_DEMO_CONTEXT.relatedConfluencePages
        : [];

  const exposedUsers = new Set();
  for (const j of jiraHits) {
    const nid = `jira:${j.key}`;
    nodes.push({
      id: nid,
      kind: 'JIRA_ISSUE',
      label: `${j.key}: ${j.summary || 'Related Ticket'}`,
      role: j.matchedFingerprint || 'Correlated Risk',
      severity: 'HIGH'
    });
    edges.push({
      from: `origin:${originKey}`,
      to: nid,
      relation: 'CROSS_TICKET_PROPAGATION'
    });
    if (j.assignee) exposedUsers.add(j.assignee);
  }

  for (const c of confHits) {
    const nid = `confluence:${c.id}`;
    nodes.push({
      id: nid,
      kind: 'CONFLUENCE_PAGE',
      label: `${c.title || `Page ${c.id}`} (${c.space || 'SPACE'})`,
      role: c.matchedFingerprint || 'Linked Spec Exposure',
      severity: 'CRITICAL'
    });
    edges.push({
      from: `origin:${originKey}`,
      to: nid,
      relation: 'CONFLUENCE_CONTEXT_EXPOSURE'
    });
    if (c.lastEditor) exposedUsers.add(c.lastEditor);
  }

  if (useSandboxFallback) {
    for (const repo of TEAMWORK_GRAPH_DEMO_CONTEXT.linkedRepositories) {
      const rid = `repo:${repo.name}`;
      nodes.push({
        id: rid,
        kind: 'REPOSITORY',
        label: `${repo.name} (${repo.branch})`,
        role: repo.exposureSignal,
        severity: 'HIGH'
      });
      edges.push({
        from: `origin:${originKey}`,
        to: rid,
        relation: 'REPO_SPEC_MIRROR'
      });
    }
    for (const w of TEAMWORK_GRAPH_DEMO_CONTEXT.originIssue.watchers) {
      exposedUsers.add(w);
    }
  }

  const crossProductHits = jiraHits.length + confHits.length;
  const baseRisk = auditReport?.riskScore ?? 0;
  const orgExposureScore = Math.min(100, baseRisk + crossProductHits * 12);
  const blastRadiusTier =
    crossProductHits >= 2 || orgExposureScore >= 85
      ? 'ORG_CRITICAL'
      : crossProductHits >= 1 || orgExposureScore >= 50
        ? 'CROSS_PRODUCT'
        : 'CONTAINED';

  return {
    protocol: 'SENTINELFORGE-TEAMWORK-GRAPH-V5',
    originKey,
    dataMode: liveJiraHits.length > 0 || liveConfluenceHits.length > 0 ? 'LIVE_WORKSPACE_GRAPH' : 'SANDBOX_CORRELATION_GRAPH',
    blastRadiusTier,
    orgExposureScore,
    totalNodesMapped: nodes.length,
    totalEdgesMapped: edges.length,
    jiraTicketsImpacted: jiraHits.length + 1,
    confluencePagesImpacted: confHits.length,
    exposedUsersCount: Math.max(exposedUsers.size, crossProductHits > 0 ? 3 : 1),
    exposedUsers: Array.from(exposedUsers),
    nodes,
    edges,
    thirdPartyCloudBytesSent: 0
  };
}

/**
 * Generates deterministic, zero-leak autonomous remediation payloads (Jira Security Incident Ticket
 * + Redacted Comment + Key Rotation Checklist) so Rovo & Forge UI can remediate with 1 click.
 */
export function buildAutonomousRemediationPlan(originKey, auditReport, graphReport) {
  const findings = auditReport?.findings || [];
  const categories = Array.from(new Set(findings.map((f) => f.category)));
  const severity = (auditReport?.riskScore || 0) >= 75 ? 'Highest' : 'High';

  const checklist = [];
  if (categories.includes('SECRET_LEAK') || categories.includes('SECRET_DLP')) {
    checklist.push('Revoke and rotate every exposed API token/key immediately in AWS IAM / Atlassian / Stripe.');
  }
  if (categories.includes('PROMPT_INJECTION')) {
    checklist.push('Quarantine untrusted ticket/page text before Rovo or MCP AI agents ingest issue context.');
  }
  if (categories.includes('PERMISSION_CHAIN') || categories.includes('IOS_PRIVACY_CHAIN') || categories.includes('MOBILE_PRIVACY')) {
    checklist.push('Replace blanket gallery/mic permissions with Android Photo Picker & hardened iOS PrivacyInfo.xcprivacy.');
  }
  if ((graphReport?.confluencePagesImpacted || 0) > 0) {
    checklist.push(
      `Audit ${graphReport.confluencePagesImpacted} correlated Confluence page(s) identified via Atlassian Teamwork Graph.`
    );
  }
  if (checklist.length === 0) {
    checklist.push('No active threats detected; log verified clean attestation in SHA-256 Forge Storage ledger.');
  }

  return {
    incidentSummary: `[SentinelForge Auto-Incident] Contain ${findings.length} security finding(s) originating in ${originKey}`,
    priority: severity,
    originKey,
    blastRadiusTier: graphReport?.blastRadiusTier || 'CONTAINED',
    orgExposureScore: graphReport?.orgExposureScore ?? auditReport?.riskScore ?? 0,
    remediationChecklist: checklist,
    safeCommentMarkdown:
      `SentinelForge v5.0 Autonomous Guard intercepted ${findings.length} risk finding(s) in ${originKey} ` +
      `(Blast Radius: ${graphReport?.blastRadiusTier || 'CONTAINED'}, Org Exposure: ${graphReport?.orgExposureScore ?? auditReport?.riskScore ?? 0}/100, External Cloud Egress: 0 B).\n` +
      `Required Actions:\n` +
      checklist.map((c, idx) => `${idx + 1}. ${c}`).join('\n'),
    thirdPartyCloudBytesSent: 0
  };
}
