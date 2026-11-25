/**
 * CyberGuard SMS & SMiShing (Short Message Service Phishing) Heuristic Analyzer Engine
 * Analyzes short text lures, urgent financial/money demands, gift card requests,
 * click-link prompts, fake delivery/banking alerts, shortened links, and sender phone shortcodes.
 */

import { analyzeUrl } from './urlAnalyzer.js';

// Comprehensive Real-World SMiShing & SMS Scam Lure Patterns
const SMISHING_PATTERNS = [
  // 1. Urgent Money / Financial Begging / Emergency Lures
  {
    pattern: /(urgent|need|send|wire|transfer|lend|borrow|emergency)\s+(money|funds|cash|\$|crypto)|urgent\s*help/i,
    weight: 30,
    title: 'Urgent Financial Aid / Emergency Money Scam',
    desc: 'Demands urgent money, wire transfers, or financial assistance. Signature of emergency impersonation scams.'
  },
  // 2. Gift Card & Untraceable Payment Demand
  {
    pattern: /(gift\s*cards?|apple\s*cards?|steam\s*cards?|google\s*play|itunes\s*card|amazon\s*card|target\s*card)/i,
    weight: 35,
    title: 'Irreversible Gift Card Payment Demand',
    desc: 'Requests untraceable gift cards. Real businesses and legitimate emergencies never demand gift cards.'
  },
  // 3. Deceptive Click-Link Call-to-Action
  {
    pattern: /(click\s*(on\s*)?(this|the)?\s*link|click\s*here|open\s*(this)?\s*link|tap\s*(this)?\s*link|visit\s*(the|this)?\s*link|follow\s*(the)?\s*link)/i,
    weight: 25,
    title: 'Click Link Redirection Lure',
    desc: 'Explicitly instructs victim to click an external link to harvest credentials or install spyware.'
  },
  // 4. "Hi Mum / Hi Dad" & Stranger False Contact Introduction
  {
    pattern: /(my\s*name\s*is|nice\s*to\s*meet\s*you|hi\s*(mom|mum|dad)|this\s*is\s*your\s*(son|daughter)|lost\s*my\s*phone|this\s*is\s*my\s*new\s*number)/i,
    weight: 20,
    title: 'Impersonation / False Identity Hook',
    desc: 'Pretends to be a relative or stranger establishing contact before requesting money or personal favors.'
  },
  // 5. Postal & Package Delivery Scams
  {
    pattern: /(usps|fedex|ups|dhl|parcel|package|delivery|postal|customs\s*fee|redelivery|shipping\s*fee|tracking\s*update)/i,
    weight: 25,
    title: 'Postal / Courier Delivery Lure',
    desc: 'Pretends to be a shipping carrier claiming a package is on hold for address update or customs fee.'
  },
  // 6. Bank Account Lockout & Fraud Alerts
  {
    pattern: /(bank|chase|wells\s*fargo|citi|bank\s*of\s*america|account\s*(locked|flagged|suspended|frozen|restricted|disabled)|unauthorized\s*(charge|login|transaction))/i,
    weight: 30,
    title: 'Bank Account Lockout Lure',
    desc: 'Pretends to be a financial institution warning of unauthorized charges or account restriction.'
  },
  // 7. OTP / 2FA Security Code Theft
  {
    pattern: /(one\s*time\s*password|verification\s*code|otp|security\s*code|6\s*digit\s*code|send\s*me\s*the\s*code|share\s*the\s*code|do\s*not\s*share)/i,
    weight: 35,
    title: '2FA / OTP Stealer Lure',
    desc: 'Attempts to trick the victim into sharing their multi-factor authentication or one-time verification password.'
  },
  // 8. Fake Job Offer / Work from Home Tasks
  {
    pattern: /(work\s*from\s*home|part\s*time\s*job|earn\s*\$?[0-9]+\s*(daily|per\s*day|hourly)|telegram\s*(job|task)|daily\s*income|hiring\s*now)/i,
    weight: 25,
    title: 'Bogus Employment / Task Scam',
    desc: 'Promises unrealistic daily income to lure victim into paying upfront deposit fees.'
  },
  // 9. Government Payout / Tax Rebate
  {
    pattern: /(tax\s*refund|irs|gov|rebate|claim\s*\$[0-9]+|stimulus\s*check|unclaimed\s*funds|subsidy)/i,
    weight: 25,
    title: 'Government / Tax Rebate Lure',
    desc: 'Baits victim with promised government payouts, subsidies, or tax refunds.'
  },
  // 10. Prize / Sweepstakes / Lottery Fraud
  {
    pattern: /(winner|won\s*\$?[0-9]+|prize|congratulations|claim\s*your\s*prize|lucky\s*draw|sweepstakes)/i,
    weight: 25,
    title: 'Prize / Sweepstakes Scam',
    desc: 'Classic reward bait claiming victim won money or devices to lure them to click a malicious link.'
  },
  // 11. Artificial Urgency & Coercion
  {
    pattern: /(urgent|immediately|within\s*24\s*hours|action\s*required|final\s*notice|final\s*warning|respond\s*asap)/i,
    weight: 20,
    title: 'Artificial Urgency Pressure',
    desc: 'Forces rapid victim compliance by creating high time pressure.'
  }
];

export function analyzeSmishing(senderPhone, messageText) {
  const flags = [];
  let threatScore = 0;

  const cleanPhone = (senderPhone || '').trim();
  const cleanMessage = (messageText || '').trim();

  // Normalize phone (strip spaces, dashes, parentheses)
  const normPhone = cleanPhone.replace(/[\s\-\(\)\.]/g, '');
  const digitsOnly = normPhone.replace(/\D/g, '');

  // 1. Sender Phone / Shortcode Heuristics
  if (normPhone.startsWith('+') && !normPhone.startsWith('+1')) {
    threatScore += 18;
    flags.push({
      type: 'WARN',
      title: 'International Sender Number',
      desc: `Sender country code (${cleanPhone.substring(0, 3)}) is foreign while delivering local service notification.`,
      weight: 18
    });
  }

  // Alphanumeric mask check (e.g. "CHASE-ALERT", "USPS-UPDATE", not normal phone numbers with spaces)
  if (/^[a-zA-Z\s_-]{3,}$/.test(cleanPhone)) {
    threatScore += 20;
    flags.push({
      type: 'WARN',
      title: 'Spoofed Alphanumeric Sender ID',
      desc: `Sender '${cleanPhone}' uses an unverified textual brand mask instead of a registered phone number.`,
      weight: 20
    });
  } else if (digitsOnly.length > 0 && digitsOnly.length < 5) {
    threatScore += 15;
    flags.push({
      type: 'WARN',
      title: 'Invalid Short Sender ID',
      desc: `Sender number '${cleanPhone}' is unusually short.`,
      weight: 15
    });
  }

  // 2. Pattern Matching against SMiShing Lures
  SMISHING_PATTERNS.forEach(rule => {
    if (rule.pattern.test(cleanMessage)) {
      threatScore += rule.weight;
      flags.push({
        type: rule.weight >= 25 ? 'FAIL' : 'WARN',
        title: rule.title,
        desc: rule.desc,
        weight: rule.weight
      });
    }
  });

  // 3. Extract and analyze embedded URLs
  const urlRegex = /(https?:\/\/[^\s<">]+|[a-z0-9-]+\.(xyz|top|link|site|info|icu)\/[^\s]+)/gi;
  const matches = cleanMessage.match(urlRegex) || [];
  const analyzedLinks = matches.map(url => analyzeUrl(url));

  if (matches.length > 0) {
    threatScore += 25;
    flags.push({
      type: 'WARN',
      title: 'Embedded SMS Link',
      desc: `Message contains ${matches.length} external URL(s). Legitimate organizations rarely send direct action links via SMS.`,
      weight: 25
    });

    analyzedLinks.forEach(link => {
      if (link.riskLevel === 'DANGER') {
        threatScore += 35;
        flags.push({
          type: 'FAIL',
          title: `Malicious Link Target (${link.hostname})`,
          desc: `Link resolves to high-risk phishing score (${link.score}/100).`,
          weight: 35
        });
      }
    });
  } else {
    // Only reduce score if no high-risk scam triggers were detected
    const hasHighRiskTrigger = flags.some(f => f.weight >= 25);
    if (!hasHighRiskTrigger) {
      threatScore = Math.max(0, threatScore - 15);
    }
  }

  const finalScore = Math.min(100, Math.max(0, threatScore));

  let riskLevel = 'SAFE';
  if (finalScore >= 70) riskLevel = 'DANGER';
  else if (finalScore >= 35) riskLevel = 'WARNING';

  return {
    senderPhone: cleanPhone,
    messageText: cleanMessage,
    score: finalScore,
    riskLevel,
    flags,
    links: analyzedLinks
  };
}
