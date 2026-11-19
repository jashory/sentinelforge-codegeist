import React, { useEffect, useState } from 'react';
import ForgeReconciler, { Badge, Box, Button, CodeBlock, Heading, SectionMessage, Stack, Text, TextArea } from '@forge/react';
import { invoke } from '@forge/bridge';

const SAMPLE_LEAK_PAYLOAD = `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz1234
<uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
<uses-permission android:name="android.permission.ACCESS_MEDIA_LOCATION" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.INTERNET" />`;

const App = () => {
  const [report, setReport] = useState(null);
  const [sandboxText, setSandboxText] = useState('');
  const [loading, setLoading] = useState(true);

  const runAudit = async (manualText = '') => {
    setLoading(true);
    try {
      const res = await invoke('auditCurrentIssue', { manualText });
      setReport(res);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runAudit();
  }, []);

  return (
    <Stack space="space.200">
      <Heading as="h3">SentinelForge Zero-Leak &amp; MCP Guard</Heading>
      <Text>
        Audits Jira issues, Confluence pages, and AndroidManifest specs inside Forge serverless RAM with 0 bytes sent to external AI APIs.
      </Text>

      {loading && <Text>Running deterministic secret &amp; permission audit...</Text>}

      {report && !loading && (
        <SectionMessage
          title={`[${report.issueKey}] Verdict: ${report.verdict} (Risk ${report.riskScore}/100 — ${report.totalFindings} findings)`}
          appearance={report.riskScore >= 70 ? 'error' : report.riskScore >= 30 ? 'warning' : 'confirmation'}
        >
          <Stack space="space.100">
            <Box>
              <Badge appearance={report.riskScore >= 70 ? 'removed' : 'added'}>
                {`EXTERNAL CLOUD BYTES: ${report.thirdPartyCloudBytesSent}`}
              </Badge>
            </Box>
            {report.findings.map((f, idx) => (
              <Text key={idx}>
                {`[${f.severity}] ${f.type} ${f.placeholder ? `-> ${f.placeholder}` : `— ${f.detail || ''}`}`}
              </Text>
            ))}
            {report.totalFindings > 0 && (
              <CodeBlock language="text" text={report.redactedPayload} />
            )}
          </Stack>
        </SectionMessage>
      )}

      <TextArea
        label="Paste config, contract, or AndroidManifest.xml for instant sandbox air-gap scan"
        value={sandboxText}
        onChange={(e) => setSandboxText(e.target.value)}
      />
      <Stack space="space.100">
        <Button appearance="primary" onClick={() => runAudit(sandboxText)}>
          Run Zero-Leak Audit
        </Button>
        <Button
          appearance="subtle"
          onClick={() => {
            setSandboxText(SAMPLE_LEAK_PAYLOAD);
            runAudit(SAMPLE_LEAK_PAYLOAD);
          }}
        >
          Test Sample Secret &amp; Permission Leak
        </Button>
      </Stack>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
