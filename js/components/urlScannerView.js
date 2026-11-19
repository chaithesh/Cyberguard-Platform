/**
 * URL & Domain Scanner View Component
 */

import { analyzeUrl } from '../engine/urlAnalyzer.js';

export function renderUrlScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="globe"></i> Real-time URL & Domain Phishing Analyzer
      </h2>
      <p class="view-subtitle">
        Inspect web URLs for typosquatting, IDN punycode spoofing, DGA entropy, high-risk TLDs, and credential harvesting patterns.
      </p>
    </div>

    <!-- Quick Sample Presets -->
    <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 20px; flex-wrap: wrap;">
      <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 600;">QUICK SAMPLES:</span>
      <button class="tab-pill sample-btn" data-url="http://paypa1-security-verify.xyz/login.php">
        <i data-lucide="alert-triangle" style="width:12px; height:12px; color:var(--crimson)"></i> PayPal Typosquat
      </button>
      <button class="tab-pill sample-btn" data-url="https://xn--80akhbyknj4f.com/google-auth">
        <i data-lucide="shield-alert" style="width:12px; height:12px; color:var(--amber)"></i> Punycode Spoof
      </button>
      <button class="tab-pill sample-btn" data-url="http://192.168.1.55/update-banking-info">
        <i data-lucide="server" style="width:12px; height:12px; color:var(--crimson)"></i> IP Host Phish
      </button>
      <button class="tab-pill sample-btn" data-url="https://github.com/security/advisories">
        <i data-lucide="check-circle" style="width:12px; height:12px; color:var(--green)"></i> Legitimate GitHub
      </button>
    </div>

    <!-- URL Input Group -->
    <div class="glass-panel" style="margin-bottom: 24px;">
      <div class="cyber-input-group">
        <i data-lucide="link" class="input-icon"></i>
        <input type="text" id="urlInput" class="cyber-input" placeholder="Enter target URL or domain (e.g., http://paypa1-security-auth.xyz/login.html)..." value="http://paypa1-security-verify.xyz/login.php">
        <button id="scanUrlBtn" class="btn-primary-cyber" style="position: absolute; right: 8px;">
          <i data-lucide="scan"></i> Scan Target
        </button>
      </div>
    </div>

    <!-- Scanner Results Container -->
    <div id="urlResultsContainer"></div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const urlInput = container.querySelector('#urlInput');
  const scanBtn = container.querySelector('#scanUrlBtn');
  const resultsContainer = container.querySelector('#urlResultsContainer');

  // Handle Preset Clicks
  container.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      runAnalysis();
    });
  });

  scanBtn.addEventListener('click', runAnalysis);
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') runAnalysis();
  });

  // Auto-run first sample on view load
  runAnalysis();

  function runAnalysis() {
    const rawUrl = urlInput.value;
    if (!rawUrl.trim()) return;

    const result = analyzeUrl(rawUrl);
    if (onScanComplete) onScanComplete(result);

    renderResults(result);
  }

  function renderResults(res) {
    if (res.error) {
      resultsContainer.innerHTML = `
        <div class="glass-panel" style="border-color: var(--crimson);">
          <h3 style="color: var(--crimson); display: flex; align-items: center; gap: 8px;">
            <i data-lucide="alert-circle"></i> Error Analyzing URL
          </h3>
          <p style="color: var(--text-secondary); margin-top: 8px;">${res.message}</p>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons();
      return;
    }

    const strokeColor = res.riskLevel === 'DANGER' ? 'var(--crimson)' : res.riskLevel === 'WARNING' ? 'var(--amber)' : 'var(--green)';
    const dashOffset = 440 - (440 * res.score) / 100;

    resultsContainer.innerHTML = `
      <div class="scanner-split-container">
        <!-- Main Analysis Breakdown -->
        <div class="glass-panel">
          <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
            <div>
              <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">TARGET HOSTNAME</span>
              <h3 style="font-family: var(--font-mono); font-size: 1.2rem; color: var(--cyan); margin-top: 2px;">
                ${res.hostname}
              </h3>
            </div>
            <span class="risk-level-badge ${res.riskLevel.toLowerCase()}">
              <i data-lucide="${res.riskLevel === 'DANGER' ? 'shield-alert' : res.riskLevel === 'WARNING' ? 'alert-triangle' : 'shield-check'}"></i>
              ${res.riskLevel} (${res.score}/100)
            </span>
          </div>

          <h4 style="font-size: 0.95rem; color: var(--text-primary); margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
            <i data-lucide="cpu" style="color: var(--cyan)"></i> Heuristic Risk Factor Breakdown
          </h4>

          <div class="features-grid">
            ${res.flags.length === 0 ? `
              <div class="feature-card">
                <div class="feature-icon-wrap pass"><i data-lucide="check"></i></div>
                <div class="feature-info">
                  <h4>Zero Threat Triggers Detected</h4>
                  <p>Domain passes standard lexical, typosquatting, and obfuscation heuristics.</p>
                </div>
              </div>
            ` : res.flags.map(flag => `
              <div class="feature-card">
                <div class="feature-icon-wrap ${flag.type.toLowerCase()}">
                  <i data-lucide="${flag.type === 'FAIL' ? 'x' : flag.type === 'WARN' ? 'alert-triangle' : 'check'}"></i>
                </div>
                <div class="feature-info">
                  <h4>${flag.title}</h4>
                  <p>${flag.desc}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Right Side Meter & WHOIS Panel -->
        <div style="display: flex; flex-direction: column; gap: 20px;">
          <!-- Score Gauge Card -->
          <div class="score-card">
            <div class="gauge-wrapper">
              <svg class="gauge-svg" viewBox="0 0 160 160">
                <circle class="gauge-bg" cx="80" cy="80" r="70"></circle>
                <circle class="gauge-fill" cx="80" cy="80" r="70" 
                        stroke="${strokeColor}" 
                        stroke-dasharray="440" 
                        stroke-dashoffset="${dashOffset}">
                </circle>
              </svg>
              <div class="gauge-center-text">
                <span class="gauge-score" style="color: ${strokeColor}">${res.score}</span>
                <span class="gauge-label">THREAT INDEX</span>
              </div>
            </div>
          </div>

          <!-- WHOIS & SSL Details Panel -->
          <div class="glass-panel" style="padding: 16px;">
            <h4 style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 12px; font-family: var(--font-mono); display: flex; align-items: center; gap: 6px;">
              <i data-lucide="lock" style="width: 14px; color: var(--cyan)"></i> SSL & WHOIS TELEMETRY
            </h4>
            <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.8rem; font-family: var(--font-mono);">
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted)">Domain Age:</span>
                <span style="color: ${res.whois.domainAgeDays < 30 ? 'var(--crimson)' : 'var(--green)'}">${res.whois.domainAgeDays} Days</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted)">SSL Protocol:</span>
                <span style="color: ${res.whois.sslValid ? 'var(--green)' : 'var(--crimson)'}">${res.whois.sslValid ? 'HTTPS Encrypted' : 'HTTP Unencrypted'}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted)">SSL Certificate:</span>
                <span style="color: #fff; text-align: right;">${res.whois.sslIssuer}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: var(--text-muted)">Domain Entropy:</span>
                <span style="color: ${res.entropy > 3.8 ? 'var(--amber)' : 'var(--text-secondary)'}">${res.entropy} bits</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
