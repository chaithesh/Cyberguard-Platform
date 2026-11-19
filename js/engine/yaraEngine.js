/**
 * CyberGuard YARA Rule Sandbox & Indicator of Compromise (IoC) Threat Engine
 * Allows SOC analysts to define, compile, and evaluate custom YARA-like threat signatures
 * against raw payload strings, URLs, or email bodies.
 */

// Default Built-in Threat Rules Database
export const DEFAULT_YARA_RULES = `rule Phish_PayPal_Credential_Harvest {
    meta:
        description = "Detects PayPal credential harvesting lures"
        severity = "HIGH"
        author = "CyberGuard SOC"
    strings:
        $brand = "paypal" nocase
        $action1 = "verify account" nocase
        $action2 = "unauthorized access" nocase
        $url_lure = ".xyz" nocase
    condition:
        $brand and ($action1 or $action2 or $url_lure)
}

rule BEC_Executive_GiftCard_Scam {
    meta:
        description = "Detects CEO Fraud / Executive Gift Card Request"
        severity = "CRITICAL"
        author = "CyberGuard SOC"
    strings:
        $phrase1 = "are you at your desk" nocase
        $phrase2 = "apple gift card" nocase
        $phrase3 = "need a quick favor" nocase
        $phrase4 = "discreet" nocase
    condition:
        ($phrase1 or $phrase3) and ($phrase2 or $phrase4)
}

rule Suspicious_Macro_Payload_Attachment {
    meta:
        description = "Detects emails containing macro executable attachments"
        severity = "HIGH"
        author = "CyberGuard SOC"
    strings:
        $ext1 = ".docm" nocase
        $ext2 = ".xlsm" nocase
        $ext3 = ".iso" nocase
        $vba = "autoopen" nocase
    condition:
        any of ($ext*) or $vba
}`;

/**
 * Parses YARA-style syntax into regex rules and evaluates against payload
 */
export function evaluateYaraRules(ruleText, payloadText) {
  const results = [];
  const rulesBlocks = ruleText.split(/\brule\s+/).filter(b => b.trim().length > 0);

  rulesBlocks.forEach(block => {
    try {
      const nameMatch = block.match(/^([A-Za-z0-9_]+)/);
      if (!nameMatch) return;
      const ruleName = nameMatch[1];

      // Extract description
      const descMatch = block.match(/description\s*=\s*"([^"]+)"/);
      const description = descMatch ? descMatch[1] : 'Custom threat detection rule';

      // Extract severity
      const sevMatch = block.match(/severity\s*=\s*"([^"]+)"/);
      const severity = sevMatch ? sevMatch[1] : 'MEDIUM';

      // Extract string definitions
      const stringsBlockMatch = block.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
      const stringDefs = [];

      if (stringsBlockMatch) {
        const lines = stringsBlockMatch[1].split('\n');
        lines.forEach(line => {
          const strMatch = line.match(/(\$[a-zA-Z0-9_]+)\s*=\s*"([^"]+)"(\s+nocase)?/);
          if (strMatch) {
            stringDefs.push({
              varName: strMatch[1],
              pattern: strMatch[2],
              nocase: !!strMatch[3]
            });
          }
        });
      }

      // Check string matches in payload
      const matchedVars = [];
      stringDefs.forEach(sDef => {
        const flags = sDef.nocase ? 'i' : '';
        const regex = new RegExp(sDef.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags);
        if (regex.test(payloadText)) {
          matchedVars.push(sDef.varName);
        }
      });

      // Simple condition evaluation (any of or condition string)
      const isMatched = stringDefs.length > 0 && matchedVars.length >= Math.ceil(stringDefs.length / 2);

      results.push({
        ruleName,
        description,
        severity,
        totalStrings: stringDefs.length,
        matchedCount: matchedVars.length,
        matchedVars,
        isMatched
      });
    } catch (e) {
      console.error('YARA parsing error:', e);
    }
  });

  return results;
}

// Global Threat Database Indicators (IoCs)
export const KNOWN_IOC_DATABASE = [
  { type: 'DOMAIN', value: 'paypa1-security-auth.xyz', category: 'Phishing Lure', risk: 'CRITICAL', added: '2026-09-20' },
  { type: 'DOMAIN', value: 'login-microsoft-verify.top', category: 'Credential Harvester', risk: 'CRITICAL', added: '2026-09-22' },
  { type: 'URL', value: 'http://192.168.1.100/chase-update/login.html', category: 'Banking Lure', risk: 'HIGH', added: '2026-09-21' },
  { type: 'HASH_MD5', value: '44d88612fea8a8f36de82e1278abb02f', category: 'Malicious PDF Payload', risk: 'CRITICAL', added: '2026-09-19' },
  { type: 'IP', value: '185.220.101.5', category: 'Phishing C2 Node', risk: 'HIGH', added: '2026-09-23' },
  { type: 'PHONE', value: '+1 (800) 555-0199', category: 'SMiShing Shortcode', risk: 'MEDIUM', added: '2026-09-18' }
];
