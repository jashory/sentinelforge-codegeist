import React, { useEffect, useState } from 'react';
import ForgeReconciler, {
  Badge,
  Box,
  Button,
  ButtonGroup,
  Heading,
  Inline,
  Lozenge,
  ProgressBar,
  SectionMessage,
  Stack,
  Text
} from '@forge/react';
import { invoke } from '@forge/bridge';

const ExecutiveDashboard = () => {
  const [dash, setDash] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const res = await invoke('getExecutiveDashboard', {});
      setDash(res);
    } finally {
      setLoading(false);
    }
  };

  const triggerRedTeamAndRefresh = async (scenarioId) => {
    setActionBusy(true);
    try {
      await invoke('runRedTeamScenario', { scenarioId });
      await loadDashboard();
    } finally {
      setActionBusy(false);
    }
  };

  const triggerAutoRemediation = async () => {
    setActionBusy(true);
    try {
      const res = await invoke('runAutonomousRemediation', { issueKey: 'KAN-1' });
      setRemediation(res);
      await loadDashboard();
    } finally {
      setActionBusy(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const totalThreats = Math.max(
    1,
    (dash?.promptInjectionTotal || 0) + (dash?.secretLeakTotal || 0) + (dash?.mobileRiskTotal || 0)
  );

  return (
    <Box padding="space.300">
      <Stack space="space.300">
        <Stack space="space.100">
          <Inline space="space.150" alignBlock="center">
            <Heading as="h2">SentinelForge v5.0 — Executive Security &amp; Teamwork Graph Dashboard</Heading>
            <Lozenge appearance="success">RUNS ON ATLASSIAN · 0 B EGRESS</Lozenge>
          </Inline>
          <Text>
            Org-wide visibility across Jira issues, Confluence specs, Rovo AI guardrails, and SHA-256 tamper-evident
            audit ledgers—built for both security engineers and engineering leadership.
          </Text>
        </Stack>

        <ButtonGroup label="Executive Security Actions">
          <Button appearance="primary" isDisabled={actionBusy} onClick={triggerAutoRemediation}>
            Run Autonomous Rovo Remediation (KAN-1)
          </Button>
          <Button appearance="danger" isDisabled={actionBusy} onClick={() => triggerRedTeamAndRefresh('indirect-prompt-injection')}>
            Simulate Prompt Injection
          </Button>
          <Button appearance="warning" isDisabled={actionBusy} onClick={() => triggerRedTeamAndRefresh('cloud-credential-card-leak')}>
            Simulate Credential Leak
          </Button>
          <Button appearance="default" isDisabled={loading} onClick={loadDashboard}>
            Refresh Telemetry
          </Button>
        </ButtonGroup>

        {remediation && (
          <SectionMessage title={`Autonomous Containment Executed (${remediation.incidentCreatedKey})`} appearance="confirmation">
            <Stack space="space.100">
              <Text>{remediation.incidentSummary}</Text>
              <Text>
                Blast Radius: {remediation.blastRadiusTier} · Exposure Score: {remediation.orgExposureScore}/100 ·
                SHA-256 Receipt Sealed in Forge Storage
              </Text>
            </Stack>
          </SectionMessage>
        )}

        {dash && !loading && (
          <>
            {/* Executive KPI Strip */}
            <Inline space="space.200" spread="space-between">
              <Box padding="space.200" backgroundColor="elevation.surface.sunken">
                <Stack space="space.050">
                  <Text>Total Workspace Audits</Text>
                  <Heading as="h3">{dash.totalAudits}</Heading>
                  <Badge appearance="primary">Forge Storage Verified</Badge>
                </Stack>
              </Box>
              <Box padding="space.200" backgroundColor="elevation.surface.sunken">
                <Stack space="space.050">
                  <Text>Critical Leaks Intercepted</Text>
                  <Heading as="h3">{dash.criticalCount}</Heading>
                  <Badge appearance="important">Blocked Before AI Egress</Badge>
                </Stack>
              </Box>
              <Box padding="space.200" backgroundColor="elevation.surface.sunken">
                <Stack space="space.050">
                  <Text>Autonomous Remediations</Text>
                  <Heading as="h3">{dash.remediatedCount}</Heading>
                  <Badge appearance="added">Rovo Active Guard</Badge>
                </Stack>
              </Box>
              <Box padding="space.200" backgroundColor="elevation.surface.sunken">
                <Stack space="space.050">
                  <Text>SHA-256 Ledger Integrity</Text>
                  <Heading as="h3">{dash.verification?.valid ? '100% VALID' : 'ALERT'}</Heading>
                  <Lozenge appearance={dash.verification?.valid ? 'success' : 'removed'}>
                    {dash.verification?.entriesVerified || 0} Sealed Blocks
                  </Lozenge>
                </Stack>
              </Box>
            </Inline>

            {/* Visual Risk Distribution Bars */}
            <Box padding="space.250" backgroundColor="elevation.surface.raised">
              <Stack space="space.150">
                <Heading as="h4">Threat Vector Breakdown (Visual Risk Telemetry)</Heading>
                <Stack space="space.050">
                  <Text>Indirect LLM Prompt Injections Blocked: {dash.promptInjectionTotal}</Text>
                  <ProgressBar value={Math.min(1, (dash.promptInjectionTotal || 0) / totalThreats)} appearance="default" />
                </Stack>
                <Stack space="space.050">
                  <Text>Enterprise Credentials &amp; PII Intercepted: {dash.secretLeakTotal}</Text>
                  <ProgressBar value={Math.min(1, (dash.secretLeakTotal || 0) / totalThreats)} appearance="default" />
                </Stack>
                <Stack space="space.050">
                  <Text>Android 8-17 &amp; iOS Privacy Chains Flagged: {dash.mobileRiskTotal}</Text>
                  <ProgressBar value={Math.min(1, (dash.mobileRiskTotal || 0) / totalThreats)} appearance="success" />
                </Stack>
              </Stack>
            </Box>

            {/* Atlassian Teamwork Graph Cross-Product Blast Radius */}
            {dash.teamworkGraph && (
              <Box padding="space.250" backgroundColor="elevation.surface.raised">
                <Stack space="space.150">
                  <Inline space="space.150" alignBlock="center">
                    <Heading as="h4">Atlassian Teamwork Graph — Cross-Product Blast Radius</Heading>
                    <Lozenge appearance="removed">{dash.teamworkGraph.blastRadiusTier}</Lozenge>
                    <Lozenge appearance="inprogress">ORG EXPOSURE {dash.teamworkGraph.orgExposureScore}/100</Lozenge>
                  </Inline>
                  <Text>
                    Mapped {dash.teamworkGraph.jiraTicketsImpacted} Jira issue(s),{' '}
                    {dash.teamworkGraph.confluencePagesImpacted} Confluence page(s), and{' '}
                    {dash.teamworkGraph.exposedUsersCount} exposed workspace user(s) strictly inside Atlassian Forge.
                  </Text>
                  <Stack space="space.100">
                    {dash.teamworkGraph.nodes.map((node) => (
                      <Inline key={node.id} space="space.100" alignBlock="center">
                        <Lozenge appearance={node.kind === 'CONFLUENCE_PAGE' ? 'moved' : node.kind === 'REPOSITORY' ? 'new' : 'inprogress'}>
                          {node.kind}
                        </Lozenge>
                        <Text>{node.label} — {node.role}</Text>
                      </Inline>
                    ))}
                  </Stack>
                </Stack>
              </Box>
            )}

            {/* SHA-256 Hash-Chained Ledger Tail */}
            <Box padding="space.250" backgroundColor="elevation.surface.sunken">
              <Stack space="space.100">
                <Heading as="h4">Recent SHA-256 Hash-Chained Audit Ledger Entries</Heading>
                {(dash.ledgerTail || []).length === 0 ? (
                  <Text>No ledger entries yet — click Simulate Credential Leak or Run Autonomous Rovo Remediation above.</Text>
                ) : (
                  dash.ledgerTail.map((entry) => (
                    <Text key={entry.seq}>
                      #{entry.seq} [{entry.target}] · {entry.verdict} (Risk {entry.riskScore}/100) · SHA-256:{' '}
                      {String(entry.entryHash || '').slice(0, 18)}...
                    </Text>
                  ))
                )}
              </Stack>
            </Box>
          </>
        )}
      </Stack>
    </Box>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <ExecutiveDashboard />
  </React.StrictMode>
);
