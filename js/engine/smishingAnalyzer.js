/**
 * CyberGuard SMS & SMiShing (Short Message Service Phishing) Heuristic Analyzer Engine
 * Analyzes short text lures, fake parcel delivery alerts, banking lockout texts,
 * suspicious shortened links, and sender phone shortcodes.
 */

import { analyzeUrl } from './urlAnalyzer.js';

// Common SMiShing Lure Patterns
const SMISHING_PATTERNS = [
  { pattern: /usps|fedex|ups|dhl|parcel|package|delivery|postal/i, weight: 20, title: 'Postal / Parcel Lure', desc: 'Pretends to be a delivery carrier requesting redelivery fee or address update.' },
  { pattern: /bank|chase|wells fargo|citi|account (locked|flagged|suspended)/i, weight: 25, title: 'Bank Account Lockout Lure', desc: 'Pretends to be a financial institution warning of unauthorized login.' },
  { pattern: /tax refund|irs|gov|rebate|claim \$[0-9]+/i, weight: 25, title: 'Government / Tax Refund Lure', desc: 'Baiting with financial tax rebates or government payout.' },
  { pattern: /winner|prize|congratulations|gift card|claim your/i, weight: 22, title: 'Prize / Sweepstakes Scam', desc: 'Classic reward bait asking user to click link to claim money or electronics.' },
  { pattern: /urgent|immediately|within 24 hours|action required/i, weight: 15, title: 'Artificial Urgency Pressure', desc: 'Forces quick victim decision-making before verifying legitimacy.' }
];

export function analyzeSmishing(senderPhone, messageText) {
  const flags = [];
  let threatScore = 0;

  const cleanPhone = senderPhone.trim();
  const cleanMessage = messageText.trim();

  // 1. Sender Phone / Shortcode Heuristics
  if (cleanPhone.startsWith('+') && !cleanPhone.startsWith('+1')) {
    threatScore += 18;
    flags.push({
      type: 'WARN',
      title: 'International Sender Number',
      desc: `Sender country code (${cleanPhone.substring(0, 3)}) is foreign while delivering local service notification.`,
      weight: 18
    });
  }

  // 5-digit shortcode check vs standard 10-digit
  if (/^\d{5,6}$/.test(cleanPhone)) {
    // 5-digit shortcodes can be legit or spoofed, minor check
  } else if (!/^\+?\d{10,15}$/.test(cleanPhone) && cleanPhone.length > 0) {
    threatScore += 20;
    flags.push({
      type: 'WARN',
      title: 'Spoofed / Alpha Sender ID',
      desc: `Sender '${cleanPhone}' uses an unverified alphanumeric sender mask.`,
      weight: 20
    });
  }

  // 2. Pattern Matching against SMiShing Lures
  SMISHING_PATTERNS.forEach(rule => {
    if (rule.pattern.test(cleanMessage)) {
      threatScore += rule.weight;
      flags.push({
        type: 'WARN',
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
      desc: `Message contains ${matches.length} external URL(s). Legitimate banks rarely send direct action links via SMS.`,
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
    // SMS with no link is rarely a phishing threat
    threatScore = Math.max(0, threatScore - 15);
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
