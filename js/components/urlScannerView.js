/**
 * URL & Domain Scanner View Component
 * Clean, simplified URL & brand typosquatting risk analyzer.
 */

import { analyzeUrl } from '../engine/urlAnalyzer.js';

const SAMPLE_URLS = [
  {
    name: 'PayPal Typosquat',
    url: 'http://paypa1-security-verify.xyz/login.php',
    icon: 'alert-triangle',
    color: 'var(--red)'
  },
  {
    name: 'Punycode Spoof',
    url: 'https://xn--80akhbyknj4f.com/google-auth',
    icon: 'shield-alert',
    color: 'var(--yellow)'
  },
  {
    name: 'IP Host Phish',
    url: 'http://192.168.1.55/update-banking-info',
    icon: 'server',
    color: 'var(--red)'
  },
  {
    name: 'Legitimate Portal',
    url: 'https://github.com/security/advisories',
    icon: 'check-circle',
    color: 'var(--green)'
  }
];

export function renderUrlScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="globe"></i> URL &amp; Domain Scanner
      </h2>
      <p class="view-subtitle">
        Inspect web URLs for typosquatting, IDN punycode spoofing, Shannon entropy, high-risk TLDs, and credential harvesting patterns.
      </p>
    </div>

    <!-- Quick Sample Presets -->
    <div class="presets-bar">
      <span class="presets-label">TRY SAMPLE:</span>
      ${SAMPLE_URLS.map(s => `
        <button class="tab-pill sample-url-btn" data-url="${s.url}">
          <i data-lucide="${s.icon}" style="width:13px; color:${s.color}"></i> ${s.name}
        </button>
      `).join('')}
    </div>

    <!-- URL Input Card -->
    <div class="clean-card" style="margin-bottom: 24px;">
      <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
        TARGET WEB ADDRESS OR DOMAIN
      </label>
      <div style="display: flex; gap: 12px; flex-wrap: wrap;">
        <input type="text" id="urlInput" class="clean-input" style="flex: 1; min-width: 260px;" placeholder="e.g. http://paypa1-security-auth.xyz/login.html" value="http://paypa1-security-verify.xyz/login.php">
        <button id="scanUrlBtn" class="btn-primary-clean">
          <i data-lucide="shield-check"></i> Inspect Target URL
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
  container.querySelectorAll('.sample-url-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      runAnalysis();
    });
  });

  scanBtn.addEventListener('click', runAnalysis);
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') runAnalysis();
  });

  // Run initial analysis
  runAnalysis();

  function runAnalysis() {
    const rawUrl = urlInput.value.trim();
    if (!rawUrl) return;

    const result = analyzeUrl(rawUrl);
    if (onScanComplete) {
      onScanComplete({
        ...result,
        category: 'URL',
        target: result.rawUrl || result.hostname
      });
    }

    renderResults(result);
  }

  function renderResults(res) {
    if (res.error) {
      resultsContainer.innerHTML = `
        <div class="clean-card" style="border-color: var(--red);">
          <h3 style="color: var(--red); display: flex; align-items: center; gap: 8px;">
            <i data-lucide="alert-circle"></i> Error Analyzing URL
          </h3>
          <p style="color: var(--text-secondary); margin-top: 8px;">${res.message}</p>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons();
      return;
    }

    const riskClass = res.riskLevel.toLowerCase();

    resultsContainer.innerHTML = `
      <div class="scanner-split-container">
        
        <!-- Left Column: Score Banner & Flag Indicators -->
        <div style="display: flex; flex-direction: column; gap: 16px;">
          
          <!-- Big Risk Score Banner -->
          <div class="score-banner-card">
            <div>
              <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
                Domain Security Assessment
              </span>
              <div style="margin-top: 4px;">
                <span class="risk-badge ${riskClass}">
                  ${res.riskLevel} (${res.score}/100)
                </span>
              </div>
              <div style="font-size: 0.88rem; color: #fff; margin-top: 8px; font-weight: 600; font-family: var(--font-mono);">
                ${res.hostname}
              </div>
            </div>

            <div class="score-circle-wrap ${riskClass}">
              <span class="score-number">${res.score}</span>
              <span class="score-sub">RISK SCORE</span>
            </div>
          </div>

          <!-- Detected Risk Indicators -->
          <div class="clean-card">
            <h4 class="card-heading" style="font-size: 0.9rem;">
              <i data-lucide="cpu" style="color: var(--primary);"></i> Detected Heuristic Triggers (${res.flags.length})
            </h4>
            <div style="display: flex; flex-direction: column; gap: 8px;">
              ${res.flags.length === 0 ? `
                <div style="font-size: 0.85rem; color: var(--green); padding: 8px;">
                  No suspicious indicators found. Domain passes standard lexical, typosquatting, and entropy checks.
                </div>
              ` : res.flags.map(f => `
                <div class="flag-card ${f.type === 'FAIL' ? 'danger' : ''}">
                  <div class="flag-title">${f.title}</div>
                  <div class="flag-desc">${f.desc}</div>
                </div>
              `).join('')}
            </div>
          </div>

        </div>

        <!-- Right Column: SSL & WHOIS Telemetry -->
        <div style="display: flex; flex-direction: column; gap: 16px;">
          <div class="clean-card">
            <h4 class="card-heading" style="font-size: 0.9rem;">
              <i data-lucide="lock" style="color: var(--primary);"></i> SSL &amp; WHOIS Telemetry
            </h4>

            <div style="display: flex; flex-direction: column; gap: 12px; font-size: 0.84rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 8px; border-bottom: 1px solid var(--border-light);">
                <span style="color: var(--text-muted);">Protocol Encryption:</span>
                <span style="font-weight: 600; color: ${res.whois.sslValid ? 'var(--green)' : 'var(--red)'};">
                  ${res.whois.sslValid ? 'HTTPS Encrypted' : 'HTTP (Insecure / Plaintext)'}
                </span>
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 8px; border-bottom: 1px solid var(--border-light);">
                <span style="color: var(--text-muted);">Domain Entropy:</span>
                <span style="font-family: var(--font-mono); color: ${parseFloat(res.entropy) > 3.8 ? 'var(--yellow)' : 'var(--text-primary)'};">
                  ${res.entropy} bits ${parseFloat(res.entropy) > 3.8 ? '(High Randomness)' : '(Normal)'}
                </span>
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 8px; border-bottom: 1px solid var(--border-light);">
                <span style="color: var(--text-muted);">Domain Age Estimate:</span>
                <span style="color: ${res.whois.domainAgeDays < 30 ? 'var(--red)' : 'var(--green)'}; font-weight: 600;">
                  ${res.whois.domainAgeDays} Days ${res.whois.domainAgeDays < 15 ? '⚠️ Newly Registered' : ''}
                </span>
              </div>

              <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: var(--text-muted);">SSL Certificate Authority:</span>
                <span style="color: #fff; font-size: 0.8rem; text-align: right;">${res.whois.sslIssuer}</span>
              </div>
            </div>
          </div>

          <!-- Quick Evaluation Guidance -->
          <div class="clean-card" style="background: rgba(14, 165, 233, 0.04); border-color: rgba(14, 165, 233, 0.2);">
            <h4 class="card-heading" style="font-size: 0.85rem; color: var(--primary);">
              <i data-lucide="info"></i> Evaluation Standard
            </h4>
            <p style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.5;">
              Domain scores are normalized from 0 to 100 based on Levenshtein brand distance, Shannon entropy, raw IP usage, Punycode character spoofing, and high-risk TLDs according to RFC standards.
            </p>
          </div>
        </div>

      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
