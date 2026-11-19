/**
 * CyberGuard Persistent Detection History Store
 * Manages scan logs, analytics aggregation, and export functionality.
 */

const STORAGE_KEY = 'cyberguard_scan_history';

// Default initial seed history for rich visual analytics on first load
const SEED_HISTORY = [
  { id: 'scan-101', timestamp: '2026-09-24 10:15', target: 'http://paypa1-security-verify.xyz/login.php', category: 'URL', riskLevel: 'DANGER', score: 92 },
  { id: 'scan-102', timestamp: '2026-09-24 09:40', target: 'Urgent BEC CEO Wire Transfer', category: 'EMAIL', riskLevel: 'DANGER', score: 88 },
  { id: 'scan-103', timestamp: '2026-09-24 09:12', target: 'https://github.com/security', category: 'URL', riskLevel: 'SAFE', score: 5 },
  { id: 'scan-104', timestamp: '2026-09-24 08:30', target: '+1 (833) 492-0199 USPS SMS Lure', category: 'SMS', riskLevel: 'DANGER', score: 78 },
  { id: 'scan-105', timestamp: '2026-09-24 07:55', target: 'IRS Warrant Arrest Phone Call', category: 'CALL', riskLevel: 'DANGER', score: 95 }
];

export function getScanHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(SEED_HISTORY));
      return SEED_HISTORY;
    }
    return JSON.parse(raw);
  } catch (e) {
    return SEED_HISTORY;
  }
}

export function saveScanRecord(record) {
  const history = getScanHistory();
  const newRecord = {
    id: 'scan-' + Date.now().toString().slice(-5),
    timestamp: new Date().toISOString().replace('T', ' ').slice(0, 16),
    target: record.target || record.hostname || 'Scanned Endpoint',
    category: record.category || 'URL',
    riskLevel: record.riskLevel || 'SAFE',
    score: record.score || 0
  };

  history.unshift(newRecord);
  // Keep last 50 entries
  if (history.length > 50) history.pop();

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch (e) {
    console.warn('LocalStorage save failed:', e);
  }

  return newRecord;
}

export function clearScanHistory() {
  localStorage.removeItem(STORAGE_KEY);
  return [];
}
