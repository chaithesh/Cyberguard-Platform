/**
 * CyberGuard Fraud Phone Call (Vishing / Voice Phishing) & STIR/SHAKEN Telemetry Engine
 * Includes Truecaller-style Reverse Caller ID Lookup, Custom Name Registration, & Community Spam Intel.
 */

const STORAGE_CUSTOM_CALLERS = 'cyberguard_custom_callers';

// Truecaller-Style Reverse Caller Identity Directory
const KNOWN_CALLER_DIRECTORY = {
  '+1 (202) 555-0143': {
    name: 'IRS Tax Audit Scammer (ROBOCALL)',
    category: 'Government Fraud',
    spamCount: 18420,
    spamScore: 98,
    carrier: 'Twilio VoIP Gateway (Unverified)',
    location: 'Washington, D.C., USA',
    lineType: 'VoIP Virtual Line',
    badge: 'CRITICAL_SPAM',
    isVerified: false
  },
  '+1 (800) 555-0188': {
    name: 'Windows Tech Support AnyDesk Scam',
    category: 'Tech Support Scam',
    spamCount: 14210,
    spamScore: 96,
    carrier: 'Bandwidth VoIP Network',
    location: 'Seattle, WA, USA',
    lineType: 'Toll-Free Virtual Line',
    badge: 'HIGH_SPAM',
    isVerified: false
  },
  '+1 (888) 555-0199': {
    name: 'Unverified Bank OTP Harvester',
    category: 'Financial Phishing',
    spamCount: 9830,
    spamScore: 92,
    carrier: 'Sinch Telecommunications',
    location: 'New York, NY, USA',
    lineType: 'VoIP Toll-Free',
    badge: 'HIGH_SPAM',
    isVerified: false
  },
  '+1 (415) 555-0122': {
    name: 'City Medical Center (Dental Clinic)',
    category: 'Healthcare & Wellness',
    spamCount: 12,
    spamScore: 2,
    carrier: 'AT&T Business Landline',
    location: 'San Francisco, CA, USA',
    lineType: 'Verified Landline',
    badge: 'VERIFIED_BUSINESS',
    isVerified: true
  }
};

/**
 * Normalizes phone numbers for flex-matching (strips spaces, dashes, brackets)
 */
function normalizePhone(phone) {
  return (phone || '').replace(/[\s\-\(\)]/g, '').toLowerCase();
}

/**
 * Gets custom caller identities saved by the user
 */
export function getCustomCallers() {
  try {
    const raw = localStorage.getItem(STORAGE_CUSTOM_CALLERS);
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

/**
 * Saves or updates a caller name identity for a phone number
 */
export function saveCustomCallerIdentity(phoneInput, name, carrier = 'Mobile Cellular', location = 'Verified Subscriber') {
  const normKey = normalizePhone(phoneInput);
  const customStore = getCustomCallers();

  customStore[normKey] = {
    phone: phoneInput.trim(),
    name: name.trim(),
    category: 'Personal / Verified Subscriber',
    spamCount: 0,
    spamScore: 0,
    carrier: carrier.trim() || 'Airtel / Jio / Verizon Mobile',
    location: location.trim() || 'Verified Location',
    lineType: 'Verified Personal Mobile',
    badge: 'VERIFIED_USER',
    isVerified: true,
    isCustomSaved: true
  };

  try {
    localStorage.setItem(STORAGE_CUSTOM_CALLERS, JSON.stringify(customStore));
  } catch (e) {
    console.warn('LocalStorage save failed:', e);
  }

  return customStore[normKey];
}

/**
 * Truecaller Reverse Caller ID Lookup Function with Custom Name Matching
 */
export function lookupCallerIdentity(phoneInput) {
  const cleanPhone = (phoneInput || '').trim();
  const normInput = normalizePhone(cleanPhone);

  // 1. Check User-Saved Custom Caller Identity Store
  const customStore = getCustomCallers();
  if (customStore[normInput]) {
    return customStore[normInput];
  }

  // 2. Check Directory (Exact or Normalized match)
  for (const key in KNOWN_CALLER_DIRECTORY) {
    if (normalizePhone(key) === normInput) {
      return { phone: cleanPhone, ...KNOWN_CALLER_DIRECTORY[key] };
    }
  }

  // 3. Dynamic Heuristic Fallback for unlisted user numbers
  const isVoip = cleanPhone.startsWith('+1 (800)') || cleanPhone.startsWith('+1 (888)') || cleanPhone.startsWith('+1 (833)');
  const digitsOnly = cleanPhone.replace(/\D/g, '');
  const hash = digitsOnly.split('').reduce((acc, char) => acc + parseInt(char, 10), 0);

  return {
    phone: cleanPhone,
    name: digitsOnly.length >= 7 ? `Subscriber Identity (#${digitsOnly.slice(-4)})` : `Unregistered Line (${cleanPhone})`,
    category: 'Mobile / Landline Subscriber',
    spamCount: (hash * 3) % 45,
    spamScore: (hash * 2) % 25,
    carrier: 'Cellular Mobile Operator (Airtel / Jio / Verizon / AT&T)',
    location: 'Verified Regional Network',
    lineType: 'Cellular Mobile',
    badge: 'UNREGISTERED_USER',
    isVerified: false,
    isUnregistered: true
  };
}

// Vishing (Voice Phishing) Threat Patterns
const VISHING_PATTERNS = [
  {
    pattern: /irs|law enforcement|warrant|arrest|police|sheriff|federal agent|court/i,
    weight: 30,
    title: 'Impersonation of Government / Law Enforcement',
    desc: 'Scammers threaten legal action or immediate arrest to instill fear and override caution.'
  },
  {
    pattern: /gift card|target card|apple card|steam card|google play card/i,
    weight: 35,
    title: 'Irreversible Payment Demand (Gift Cards)',
    desc: 'Government agencies and real banks NEVER accept gift cards as payment for fees or bail.'
  },
  {
    pattern: /one time password|otp|verification code|security code|read me the code/i,
    weight: 35,
    title: '2FA / OTP Credential Harvesting Lure',
    desc: 'Caller attempts to trick victim into revealing active multi-factor authentication (MFA) codes.'
  },
  {
    pattern: /anydesk|teamviewer|quicksupport|logmein|remote access|download this software/i,
    weight: 30,
    title: 'Remote Access Trojan (RAT) Installation Lure',
    desc: 'Tech support scam tactic attempting to gain full remote control of victim computer or phone.'
  },
  {
    pattern: /microsoft support|windows security|virus detected|computer infected/i,
    weight: 25,
    title: 'Fake Tech Support Lure',
    desc: 'Unsolicited caller claims your computer has a virus or security breach.'
  }
];

// STIR/SHAKEN Attestation Definitions
const STIR_SHAKEN_LEVELS = {
  FULL: { level: 'A - Full Attestation', desc: 'Carrier verified both caller identity and authority to use the phone number.', risk: 'SAFE' },
  PARTIAL: { level: 'B - Partial Attestation', desc: 'Carrier verified call origin but cannot verify right to use caller ID number.', risk: 'WARN' },
  GATEWAY: { level: 'C - Gateway / Unverified', desc: 'Call entered network from international gateway or unverified VoIP provider. High spoofing risk.', risk: 'FAIL' }
};

export function analyzeVishingCall(callerPhone, callTranscript, selectedAttestation = 'GATEWAY') {
  const flags = [];
  let threatScore = 0;

  const cleanPhone = (callerPhone || '').trim();
  const transcriptText = (callTranscript || '').trim();

  // Truecaller Caller ID Lookup Integration
  const truecallerIntel = lookupCallerIdentity(cleanPhone);

  if (truecallerIntel.spamScore >= 70) {
    threatScore += 30;
    flags.push({
      type: 'FAIL',
      title: `Truecaller Community Spam Score: ${truecallerIntel.spamScore}%`,
      desc: `Flagged by ${truecallerIntel.spamCount.toLocaleString()} users as "${truecallerIntel.name}".`,
      weight: 30
    });
  }

  if (selectedAttestation === 'GATEWAY') {
    threatScore += 30;
    flags.push({
      type: 'FAIL',
      title: 'STIR/SHAKEN Attestation: Level C (Unverified Gateway)',
      desc: 'Telecom carrier flag indicates unverified caller ID identity. High likelihood of caller ID spoofing.',
      weight: 30
    });
  }

  VISHING_PATTERNS.forEach(rule => {
    if (rule.pattern.test(transcriptText)) {
      threatScore += rule.weight;
      flags.push({
        type: rule.weight >= 30 ? 'FAIL' : 'WARN',
        title: rule.title,
        desc: rule.desc,
        weight: rule.weight
      });
    }
  });

  const finalScore = Math.min(100, Math.max(0, threatScore));

  let riskLevel = 'SAFE';
  if (finalScore >= 65) riskLevel = 'DANGER';
  else if (finalScore >= 35) riskLevel = 'WARNING';

  return {
    callerPhone: cleanPhone,
    callerIntel: truecallerIntel,
    attestationInfo: STIR_SHAKEN_LEVELS[selectedAttestation] || STIR_SHAKEN_LEVELS.GATEWAY,
    score: finalScore,
    riskLevel,
    flags
  };
}
