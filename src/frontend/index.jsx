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
  const [sandboxText, setSandboxText] = useState('');
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');

  const runAudit = async (manualText = '') => {
    setLoading(true);
    setErrorMsg('');
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
    try {
      const res = await invoke('runRedTeamScenario', { scenarioId });
      setReport(res);
    } catch (err) {
      setErrorMsg(String(err?.message || err || 'Red-Team replay failed'));
    } finally {
      setLoading(false);
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

  return (
    <Stack space="space.200">
      <Heading as="h3">SentinelForge v4.0 — Zero-Leak, Prompt-Injection &amp; MCP Guard</Heading>
      <Text>
        4-Layer Native Atlassian Forge Security Shield: blocks indirect LLM prompt injections, Atlassian/AWS/Stripe secrets,
        and Android 8-17 / Apple iOS privacy chains with 0 external egress and a SHA-256 hash-chained Forge Storage ledger.
      </Text>

      <Stack space="space.100">
        <Text>1-Click Live Red-Team Replay Simulator (For Instant Judge Verification):</Text>
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
          <Button appearance="subtle" onClick={verifyLedger}>
            Verify SHA-256 Ledger
          </Button>
        </ButtonGroup>
      </Stack>

      {loading && <Text>Executing 4-layer zero-egress audit and sealing SHA-256 ledger...</Text>}

      {errorMsg && !loading && (
        <SectionMessage title="Audit notice" appearance="warning">
          <Text>{errorMsg}</Text>
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
              <Badge appearance={report.ledgerVerification?.valid !== false ? 'added' : 'removed'}>
                {`SHA-256 CHAIN: ${report.ledgerVerification?.valid !== false ? 'VERIFIED' : 'TAMPERED'} (${report.ledgerVerification?.entriesVerified || 0})`}
              </Badge>
            </Box>

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
          Run 4-Layer Zero-Leak Audit
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
