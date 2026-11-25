/**
 * CyberGuard Email Header & Content Heuristic Inspector Engine
 * Analyzes authentication headers (SPF, DKIM, DMARC), Return-Path alignment,
 * Display Name spoofing, executive/brand impersonation via free webmail,
 * cryptocurrency extortion wallets, NLP psychological triggers, embedded links, and payload attachments.
 */

import { analyzeUrl } from './urlAnalyzer.js';

// Free public webmail provider domains commonly abused in display-name impersonation
const FREE_WEBMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'protonmail.com', 'mail.com', 'yandex.com', 'zoho.com', 'icloud.com', 'live.com'
];

// Executive and administrative corporate titles frequently impersonated in Business Email Compromise (BEC)
const EXECUTIVE_KEYWORDS = [
  'ceo', 'cfo', 'coo', 'president', 'director', 'executive', 'chief',
  'it support', 'helpdesk', 'hr department', 'payroll team', 'security team',
  'admin', 'administrator', 'billing department'
];

// Protected high-target brands for display name checks
const PROTECTED_BRANDS = [
  'paypal', 'google', 'microsoft', 'apple', 'netflix', 'amazon', 'chase',
  'bank of america', 'wells fargo', 'dhl', 'fedex', 'usps', 'ups', 'meta', 'facebook', 'stripe'
];

// High pressure psychological lure phrases used in spear phishing
const PSYCHOLOGICAL_TRIGGERS = [
  { phrase: 'account suspended', weight: 20, desc: 'Fake account termination scare tactic' },
  { phrase: 'unauthorized login', weight: 18, desc: 'False security breach alert' },
  { phrase: 'wire transfer', weight: 25, desc: 'Urgent BEC / Financial wire lure' },
  { phrase: 'immediate verification required', weight: 22, desc: 'High urgency call-to-action' },
  { phrase: 'click here to restore', weight: 20, desc: 'Phishing link insertion' },
  { phrase: 'gift card', weight: 25, desc: 'CEO fraud / Gift card purchase lure' },
  { phrase: 'invoice overdue', weight: 18, desc: 'Malicious attachment billing lure' },
  { phrase: 'payroll update', weight: 22, desc: 'Direct deposit redirect phishing' },
  { phrase: 'password expires today', weight: 20, desc: 'Urgent credential harvesting scare' },
  { phrase: 'confirm your identity', weight: 18, desc: 'Identity theft luring' },
  { phrase: 'within 24 hours', weight: 15, desc: 'Artificial deadline urgency' },
  { phrase: 'final notice', weight: 20, desc: 'Coercive final warning scare' },
  { phrase: 'bitcoin', weight: 20, desc: 'Cryptocurrency payment lure' }
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

  // Extract Display Name and From email address (using last angle bracket for actual envelope)
  let displayName = '';
  let fromEmail = '';
  const lastAngleIdx = fromHeader.lastIndexOf('<');
  const endAngleIdx = fromHeader.lastIndexOf('>');
  if (lastAngleIdx !== -1 && endAngleIdx > lastAngleIdx) {
    fromEmail = fromHeader.substring(lastAngleIdx + 1, endAngleIdx).trim();
    displayName = fromHeader.substring(0, lastAngleIdx).trim().replace(/^["']|["']$/g, '').trim();
  } else {
    fromEmail = fromHeader.replace(/^["']|["']$/g, '').trim();
  }
  const fromDomain = fromEmail.split('@')[1] || '';

  const returnMatch = returnPath.match(/<([^>]+)>/) || [null, returnPath];
  const returnEmail = (returnMatch[1] || '').trim();
  const returnDomain = returnEmail.split('@')[1] || '';

  // 1a. Display Name Spoofing: Display name contains an embedded email mismatching the real address
  const emailInDisplayName = displayName.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (emailInDisplayName && fromDomain && emailInDisplayName[1].toLowerCase() !== fromDomain.toLowerCase()) {
    threatScore += 45;
    flags.push({
      type: 'FAIL',
      title: 'Deceptive Display Name Spoofing',
      desc: `Display name mimics official email '${emailInDisplayName[0]}' while actual sending inbox is '${fromEmail}'. Classic mobile client deception tactic.`,
      weight: 45
    });
  }

  // 1b. Executive / Brand Impersonation via Free Webmail
  const lowerDisplay = displayName.toLowerCase();
  const claimsExecutiveOrBrand = EXECUTIVE_KEYWORDS.some(kw => lowerDisplay.includes(kw)) || PROTECTED_BRANDS.some(b => lowerDisplay.includes(b));
  if (claimsExecutiveOrBrand && FREE_WEBMAIL_DOMAINS.includes(fromDomain.toLowerCase())) {
    threatScore += 40;
    flags.push({
      type: 'FAIL',
      title: 'Executive / Brand Impersonation via Webmail',
      desc: `Display name claims corporate/executive identity '${displayName}' but sends from a free public webmail address (@${fromDomain}).`,
      weight: 40
    });
  }

  // 1c. From vs Return-Path Domain Alignment Check
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

  // 3a. NLP Urgency & Psychological Lure Scanner
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

  // 3b. Cryptocurrency Ransomware & Extortion Wallet Scanner
  const btcMatches = emailText.match(/\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g) || [];
  const ethMatches = emailText.match(/\b0x[a-fA-F0-9]{40}\b/g) || [];
  const cryptoWallets = [...new Set([...btcMatches, ...ethMatches])];

  if (cryptoWallets.length > 0) {
    threatScore += 35;
    flags.push({
      type: 'FAIL',
      title: 'Cryptocurrency Wallet Address Detected',
      desc: `Email body contains cryptocurrency address(es): [ ${cryptoWallets.join(', ')} ]. Signature of extortion, blackmail, or ransomware demand.`,
      weight: 35
    });
  }

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
    displayName,
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
    cryptoWallets,
    links: analyzedLinks,
    suspiciousFiles: [...new Set(suspiciousFiles)]
  };
}
