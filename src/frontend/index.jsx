import React, { useEffect, useState } from 'react';
import ForgeReconciler, {
  Badge,
  Box,
  Button,
  ButtonGroup,
  CodeBlock,
  Heading,
  SectionMessage,
  Stack,
  Text,
  TextArea
} from '@forge/react';
import { invoke } from '@forge/bridge';

const App = () => {
  const [report, setReport] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [sandboxText, setSandboxText] = useState('');
  const [loading, setLoading] = useState(true);
  const [remediating, setRemediating] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const runAudit = async (manualText = '') => {
    setLoading(true);
    setErrorMsg('');
    setRemediation(null);
    try {
      const res = await invoke('auditCurrentIssue', { manualText });
      setReport(res);
    } catch (err) {
      setErrorMsg(String(err?.message || err || 'Audit invocation failed'));
    } finally {
      setLoading(false);
    }
  };

  const fireRedTeam = async (scenarioId) => {
    setLoading(true);
    setErrorMsg('');
    setRemediation(null);
    try {
      const res = await invoke('runRedTeamScenario', { scenarioId });
      setReport(res);
    } catch (err) {
      setErrorMsg(String(err?.message || err || 'Red-Team replay failed'));
    } finally {
      setLoading(false);
    }
  };

  const triggerAutoRemediation = async () => {
    setRemediating(true);
    setErrorMsg('');
    try {
      const res = await invoke('runAutonomousRemediation', {
        issueKey: report?.issueKey,
        payloadText: sandboxText || undefined
      });
      setRemediation(res);
    } catch (err) {
      setErrorMsg(String(err?.message || err || 'Autonomous remediation failed'));
    } finally {
      setRemediating(false);
    }
  };

  const verifyLedger = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await invoke('verifyAuditLedger', {});
      setReport((prev) =>
        prev
          ? {
              ...prev,
              ledgerVerification: res.verification,
              ledgerTail: res.ledgerTail
            }
          : {
              issueKey: 'SHA-256 AUDIT LEDGER',
              verdict: res.verification.valid ? 'CLEAN_PASS' : 'BLOCK_AND_SANITIZE',
              riskScore: res.verification.valid ? 0 : 100,
              totalFindings: 0,
              promptInjectionsBlocked: 0,
              secretsBlocked: 0,
              mobileRisksBlocked: 0,
              findings: [],
              redactedPayload: '',
              thirdPartyCloudBytesSent: 0,
              ledgerVerification: res.verification,
              ledgerTail: res.ledgerTail
            }
      );
    } catch (err) {
      setErrorMsg(String(err?.message || err || 'Ledger verification failed'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runAudit();
  }, []);

  const graph = report?.teamworkGraph;

  return (
    <Stack space="space.200">
      <Heading as="h3">SentinelForge v5.0 — Teamwork Graph Blast-Radius &amp; Autonomous Rovo Guard</Heading>
      <Text>
        Runs natively on Atlassian Forge (0 bytes external egress): correlates leaked credentials, indirect LLM prompt
        injections, and Android/iOS privacy risks across Jira and Confluence via Atlassian Teamwork Graph, executes
        1-click autonomous containment, and seals every event in a SHA-256 Forge Storage ledger.
      </Text>

      <Stack space="space.100">
        <Text>1-Click Live Red-Team &amp; Autonomous Containment Controls:</Text>
        <ButtonGroup label="Red-Team Attack Replay">
          <Button appearance="danger" onClick={() => fireRedTeam('indirect-prompt-injection')}>
            Fire Prompt Injection
          </Button>
          <Button appearance="warning" onClick={() => fireRedTeam('cloud-credential-card-leak')}>
            Fire Cloud Key Leak
          </Button>
          <Button appearance="default" onClick={() => fireRedTeam('mobile-privacy-android-ios')}>
            Fire Android/iOS Spec
          </Button>
          <Button appearance="primary" isDisabled={remediating} onClick={triggerAutoRemediation}>
            {remediating ? 'Containing...' : 'Auto-Remediate & Open Incident'}
          </Button>
          <Button appearance="subtle" onClick={verifyLedger}>
            Verify SHA-256 Ledger
          </Button>
        </ButtonGroup>
      </Stack>

      {loading && <Text>Correlating Atlassian Teamwork Graph blast radius and sealing SHA-256 ledger...</Text>}

      {errorMsg && !loading && (
        <SectionMessage title="Audit notice" appearance="warning">
          <Text>{errorMsg}</Text>
        </SectionMessage>
      )}

      {remediation && (
        <SectionMessage
          title={`Autonomous Containment Executed — Incident ${remediation.incidentCreatedKey} (${remediation.blastRadiusTier})`}
          appearance="confirmation"
        >
          <Stack space="space.100">
            <Text>{remediation.incidentSummary}</Text>
            <CodeBlock language="text" text={remediation.safeCommentMarkdown} />
          </Stack>
        </SectionMessage>
      )}

      {report && !loading && (
        <SectionMessage
          title={`[${report.issueKey}] Verdict: ${report.verdict} (Risk ${report.riskScore}/100 — ${report.totalFindings} findings)`}
          appearance={report.riskScore >= 70 ? 'error' : report.riskScore >= 30 ? 'warning' : 'confirmation'}
        >
          <Stack space="space.100">
            <Box>
              <Badge appearance="added">{`EXTERNAL CLOUD BYTES: ${report.thirdPartyCloudBytesSent}`}</Badge>
              <Badge appearance={report.promptInjectionsBlocked > 0 ? 'removed' : 'default'}>
                {`PROMPT INJECTIONS: ${report.promptInjectionsBlocked || 0}`}
              </Badge>
              <Badge appearance={report.secretsBlocked > 0 ? 'removed' : 'default'}>
                {`SECRETS: ${report.secretsBlocked || 0}`}
              </Badge>
              {graph && (
                <Badge appearance={graph.blastRadiusTier === 'ORG_CRITICAL' ? 'removed' : 'inprogress'}>
                  {`TEAMWORK GRAPH: ${graph.blastRadiusTier} (${graph.totalNodesMapped} NODES)`}
                </Badge>
              )}
              <Badge appearance={report.ledgerVerification?.valid !== false ? 'added' : 'removed'}>
                {`SHA-256 CHAIN: ${report.ledgerVerification?.valid !== false ? 'VERIFIED' : 'TAMPERED'} (${report.ledgerVerification?.entriesVerified || 0})`}
              </Badge>
            </Box>

            {graph && graph.nodes && graph.nodes.length > 1 && (
              <Stack space="space.050">
                <Text>
                  {`Teamwork Graph Blast Radius: ${graph.jiraTicketsImpacted} Jira issue(s), ${graph.confluencePagesImpacted} Confluence page(s), ${graph.exposedUsersCount} exposed user(s) — Org Exposure ${graph.orgExposureScore}/100`}
                </Text>
                {graph.nodes.map((node) => (
                  <Text key={node.id}>
                    {`• [${node.kind}] ${node.label} — ${node.role} (${node.severity})`}
                  </Text>
                ))}
              </Stack>
            )}

            {report.findings.map((f, idx) => (
              <Text key={idx}>
                {`[${f.severity}] [${f.category}] ${f.type} ${f.placeholder ? `-> ${f.placeholder}` : ''} ${f.detail ? `— ${f.detail}` : ''}`}
              </Text>
            ))}

            {report.totalFindings > 0 && report.redactedPayload && (
              <CodeBlock language="text" text={report.redactedPayload} />
            )}

            {report.ledgerTail && report.ledgerTail.length > 0 && (
              <CodeBlock
                language="text"
                text={report.ledgerTail
                  .map(
                    (e) =>
                      `#${e.seq} [${e.verdict} ${e.riskScore}/100] ${e.target} | sha256=${String(e.entryHash).slice(0, 16)}... <- prev=${String(e.prevHash).slice(0, 12)}...`
                  )
                  .join('\n')}
              />
            )}
          </Stack>
        </SectionMessage>
      )}

      <TextArea
        label="Paste Jira ticket, Confluence spec, AndroidManifest.xml, or Apple iOS Info.plist for air-gap audit"
        value={sandboxText}
        onChange={(e) => setSandboxText(e.target.value)}
      />
      <ButtonGroup label="Custom Audit">
        <Button appearance="primary" onClick={() => runAudit(sandboxText)}>
          Run Teamwork Graph &amp; Zero-Leak Audit
        </Button>
        <Button appearance="subtle" onClick={() => runAudit('')}>
          Re-Audit Current Page / Issue
        </Button>
      </ButtonGroup>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
