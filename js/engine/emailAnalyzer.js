/**
 * CyberGuard Email Header & Content Heuristic Inspector Engine
 * Analyzes authentication headers (SPF, DKIM, DMARC), Return-Path alignment,
 * NLP psychological triggers, embedded links, and payload attachments.
 */

import { analyzeUrl } from './urlAnalyzer.js';

// High pressure psychological lure phrases used in spear phishing
const PSYCHOLOGICAL_TRIGGERS = [
  { phrase: 'account suspended', weight: 20, desc: 'Fake account termination scare tactic' },
  { phrase: 'unauthorized login', weight: 18, desc: 'False security breach alert' },
  { phrase: 'wire transfer', weight: 25, desc: 'Urgent BEC / Financial lure' },
  { phrase: 'immediate verification required', weight: 22, desc: 'High urgency call-to-action' },
  { phrase: 'click here to restore', weight: 20, desc: 'Phishing link insertion' },
  { phrase: 'gift card', weight: 25, desc: 'CEO fraud / Gift card scam lure' },
  { phrase: 'invoice overdue', weight: 18, desc: 'Malicious attachment billing lure' },
  { phrase: 'payroll update', weight: 22, desc: 'Direct deposit redirect phishing' },
  { phrase: 'password expires today', weight: 20, desc: 'Urgent credential harvesting scare' },
  { phrase: 'confirm your identity', weight: 18, desc: 'Identity theft luring' }
];

// Dangerous file extensions frequently embedded in email phishing
const DANGEROUS_EXTENSIONS = ['.exe', '.scr', '.vbs', '.js', '.iso', '.img', '.bat', '.cmd', '.ps1', '.hta', '.docm', '.xlsm'];

/**
 * Extracts links from text content using regex
 */
function extractUrlsFromText(text) {
  const urlRegex = /(https?:\/\/[^\s<">]+)/gi;
  const matches = text.match(urlRegex) || [];
  return [...new Set(matches)];
}

/**
 * Parses raw email header block into key-value pairs
 */
function parseEmailHeaders(headerText) {
  const headers = {};
  const lines = headerText.split(/\r?\n/);
  let currentHeader = null;

  lines.forEach(line => {
    if (/^\s+[^\s]/.test(line) && currentHeader) {
      // Continuation line
      headers[currentHeader] += ' ' + line.trim();
    } else {
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        currentHeader = line.substring(0, colonIdx).trim().toLowerCase();
        headers[currentHeader] = line.substring(colonIdx + 1).trim();
      }
    }
  });

  return headers;
}

/**
 * Main Email Inspection Function
 */
export function analyzeEmail(emailText, headerText = '') {
  const flags = [];
  let threatScore = 0;

  const parsedHeaders = parseEmailHeaders(headerText);
  const fromHeader = parsedHeaders['from'] || '';
  const returnPath = parsedHeaders['return-path'] || '';
  const subject = parsedHeaders['subject'] || '';
  const authResults = parsedHeaders['authentication-results'] || '';

  // Extract From email address
  const fromMatch = fromHeader.match(/<([^>]+)>/) || [null, fromHeader];
  const fromEmail = (fromMatch[1] || '').trim();
  const fromDomain = fromEmail.split('@')[1] || '';

  const returnMatch = returnPath.match(/<([^>]+)>/) || [null, returnPath];
  const returnEmail = (returnMatch[1] || '').trim();
  const returnDomain = returnEmail.split('@')[1] || '';

  // 1. From vs Return-Path Domain Alignment Check
  if (fromDomain && returnDomain && fromDomain.toLowerCase() !== returnDomain.toLowerCase()) {
    threatScore += 35;
    flags.push({
      type: 'FAIL',
      title: 'Sender Spoofing (Return-Path Mismatch)',
      desc: `From domain (${fromDomain}) does not match Return-Path domain (${returnDomain}). Signature of address spoofing.`,
      weight: 35
    });
  }

  // 2. SPF / DKIM / DMARC Header Authentication Check
  let spfStatus = 'PASS';
  let dkimStatus = 'PASS';
  let dmarcStatus = 'PASS';

  if (authResults) {
    if (authResults.includes('spf=fail') || authResults.includes('spf=softfail')) {
      spfStatus = 'FAIL';
      threatScore += 30;
      flags.push({
        type: 'FAIL',
        title: 'SPF Authentication Failed',
        desc: 'Sending IP server is not authorized in SPF record for domain ' + fromDomain,
        weight: 30
      });
    }
    if (authResults.includes('dkim=fail')) {
      dkimStatus = 'FAIL';
      threatScore += 25;
      flags.push({
        type: 'FAIL',
        title: 'DKIM Cryptographic Signature Invalid',
        desc: 'Email body or headers were modified in transit or signed with untrusted key.',
        weight: 25
      });
    }
    if (authResults.includes('dmarc=fail')) {
      dmarcStatus = 'FAIL';
      threatScore += 35;
      flags.push({
        type: 'FAIL',
        title: 'DMARC Enforcement Failed',
        desc: 'Email failed domain alignment policy.',
        weight: 35
      });
    }
  } else if (headerText.length > 20) {
    // If headers provided but missing authentication results
    spfStatus = 'UNKNOWN';
    dkimStatus = 'UNKNOWN';
    dmarcStatus = 'UNKNOWN';
    threatScore += 15;
    flags.push({
      type: 'WARN',
      title: 'Missing Security Signatures',
      desc: 'Email headers lack verified SPF/DKIM/DMARC authentication records.',
      weight: 15
    });
  }

  // 3. NLP Urgency & Psychological Lure Scanner
  const combinedContent = (subject + ' ' + emailText).toLowerCase();
  const matchedTriggers = [];

  PSYCHOLOGICAL_TRIGGERS.forEach(trigger => {
    if (combinedContent.includes(trigger.phrase)) {
      matchedTriggers.push(trigger);
      threatScore += trigger.weight;
      flags.push({
        type: 'WARN',
        title: `Phishing Lure: "${trigger.phrase.toUpperCase()}"`,
        desc: trigger.desc,
        weight: trigger.weight
      });
    }
  });

  // 4. Extracted Links & Sub-Analysis
  const extractedUrls = extractUrlsFromText(emailText);
  const analyzedLinks = extractedUrls.map(url => analyzeUrl(url));

  const dangerousLinks = analyzedLinks.filter(link => link.riskLevel === 'DANGER' || link.riskLevel === 'WARNING');
  if (dangerousLinks.length > 0) {
    threatScore += 35;
    flags.push({
      type: 'FAIL',
      title: `High-Risk Embedded Links (${dangerousLinks.length})`,
      desc: `Contains ${dangerousLinks.length} malicious or typosquatted URLs in body content.`,
      weight: 35
    });
  }

  // 5. Dangerous Attachment Payload Detection
  const attachmentMatches = emailText.match(/\b[\w-]+\.([a-z0-9]{2,4})\b/gi) || [];
  const suspiciousFiles = attachmentMatches.filter(filename => {
    const ext = '.' + filename.split('.').pop().toLowerCase();
    return DANGEROUS_EXTENSIONS.includes(ext);
  });

  if (suspiciousFiles.length > 0) {
    threatScore += 40;
    flags.push({
      type: 'FAIL',
      title: 'Dangerous Attachment Payload Detected',
      desc: `Detected executable/script attachment patterns: [ ${[...new Set(suspiciousFiles)].join(', ')} ]`,
      weight: 40
    });
  }

  const finalScore = Math.min(100, Math.max(0, threatScore));

  let riskLevel = 'SAFE';
  if (finalScore >= 70) riskLevel = 'DANGER';
  else if (finalScore >= 35) riskLevel = 'WARNING';

  return {
    fromEmail,
    fromDomain,
    returnDomain,
    subject,
    headers: parsedHeaders,
    authentication: { spfStatus, dkimStatus, dmarcStatus },
    score: finalScore,
    riskLevel,
    flags,
    matchedTriggers,
    links: analyzedLinks,
    suspiciousFiles: [...new Set(suspiciousFiles)]
  };
}
