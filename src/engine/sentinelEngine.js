/**
 * SentinelForge Core Zero-Leak Security & Permission Audit Engine
 * Shared by Forge Resolver, Rovo Agent Action, Jira Auto-Trigger, and Atlassian MCP Server.
 * Zero outbound third-party AI or telemetry calls.
 */

export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let ent = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function luhnValid(raw) {
  const digits = String(raw || '').replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (dbl) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function auditEngineeringPayload(rawText) {
  const input = String(rawText || '');
  let redacted = input;
  const findings = [];
  let seq = 0;

  const secretPatterns = [
    { type: 'PRIVATE_KEY_BLOCK', severity: 'CRITICAL', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    { type: 'AWS_ACCESS_KEY', severity: 'CRITICAL', regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { type: 'ATLASSIAN_API_TOKEN', severity: 'CRITICAL', regex: /\bATATT3xFfGF0[A-Za-z0-9_=-]{20,}\b/g },
    { type: 'GITHUB_PAT', severity: 'CRITICAL', regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
    { type: 'BEARER_JWT', severity: 'HIGH', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { type: 'IBAN_FINANCIAL', severity: 'HIGH', regex: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,26}\b/g },
    { type: 'NID_OR_SSN', severity: 'HIGH', regex: /\b(?:NID|SSN|Passport)[\s:#-]*[A-Z0-9-]{7,17}\b/gi }
  ];

  for (const rule of secretPatterns) {
    redacted = redacted.replace(rule.regex, (m) => {
      seq += 1;
      const token = `[SENTINEL_REDACTED_${rule.type}_${seq}]`;
      findings.push({
        category: 'SECRET_LEAK',
        type: rule.type,
        severity: rule.severity,
        placeholder: token,
        length: m.length
      });
      return token;
    });
  }

  redacted = redacted.replace(/\b(?:\d[ -]*?){13,19}\b/g, (m) => {
    if (!luhnValid(m)) return m;
    seq += 1;
    const token = `[SENTINEL_REDACTED_PAYMENT_CARD_${seq}]`;
    findings.push({
      category: 'SECRET_LEAK',
      type: 'PAYMENT_CARD_LUHN',
      severity: 'CRITICAL',
      placeholder: token,
      length: m.length
    });
    return token;
  });

  redacted = redacted.replace(/\b[A-Za-z0-9_/+=-]{28,80}\b/g, (m) => {
    if (m.includes('SENTINEL_REDACTED_')) return m;
    const ent = shannonEntropy(m);
    if (ent >= 4.25 && /[a-z]/.test(m) && /[A-Z]/.test(m) && /[0-9]/.test(m)) {
      seq += 1;
      const token = `[SENTINEL_REDACTED_HIGH_ENTROPY_${seq}]`;
      findings.push({
        category: 'SECRET_LEAK',
        type: 'HIGH_ENTROPY_CREDENTIAL',
        severity: 'HIGH',
        placeholder: token,
        entropy: Number(ent.toFixed(2))
      });
      return token;
    }
    return m;
  });

  // Mobile Permission Silent-Harvesting Chain Audit inside Jira/Confluence specs
  const perms = [...new Set([...input.matchAll(/android\.permission\.([A-Z0-9_]+)/g)].map((m) => m[1]))];
  const permSet = new Set(perms);
  if ((permSet.has('READ_MEDIA_IMAGES') || permSet.has('READ_EXTERNAL_STORAGE')) && permSet.has('INTERNET')) {
    findings.push({
      category: 'PERMISSION_CHAIN',
      type: 'SILENT_CAMERA_ROLL_HARVESTING',
      severity: 'CRITICAL',
      detail: 'Blanket Gallery + Internet permissions enable unshared photo & EXIF exfiltration without root.'
    });
  }
  if (permSet.has('RECORD_AUDIO') && permSet.has('INTERNET')) {
    findings.push({
      category: 'PERMISSION_CHAIN',
      type: 'AMBIENT_MICROPHONE_EGRESS',
      severity: 'CRITICAL',
      detail: 'Microphone + Internet permissions require foreground-only consent enforcement.'
    });
  }
  if (permSet.has('READ_SMS') && permSet.has('INTERNET')) {
    findings.push({
      category: 'PERMISSION_CHAIN',
      type: 'SMS_OTP_INTERCEPTION',
      severity: 'CRITICAL',
      detail: 'SMS read access paired with Internet exposes banking & 2FA verification codes.'
    });
  }

  const riskScore = Math.min(
    100,
    findings.reduce((sum, f) => sum + (f.severity === 'CRITICAL' ? 35 : f.severity === 'HIGH' ? 20 : 10), 0)
  );

  return {
    riskScore,
    verdict: riskScore >= 70 ? 'BLOCK_AND_SANITIZE' : riskScore >= 30 ? 'REVIEW_REQUIRED' : 'CLEAN_PASS',
    totalFindings: findings.length,
    findings,
    redactedPayload: redacted,
    thirdPartyCloudBytesSent: 0
  };
}

export function extractAdfText(node) {
  if (!node) return '';
  if (typeof node === 'string') return node;
  if (node.type === 'text') return node.text || '';
  if (node.type === 'hardBreak') return '\n';
  if (Array.isArray(node.content)) {
    const childTexts = node.content.map((child) => extractAdfText(child));
    const blockTypes = new Set(['paragraph', 'heading', 'codeBlock', 'listItem', 'blockquote']);
    const separator = blockTypes.has(node.type) ? '' : '\n';
    const joined = childTexts.join(separator);
    return blockTypes.has(node.type) ? `${joined}\n` : joined;
  }
  return '';
}

export function stripHtmlToText(html = '') {
  return String(html || '')
    .replace(/<\/(p|div|h[1-6]|li|tr|pre|blockquote)>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

