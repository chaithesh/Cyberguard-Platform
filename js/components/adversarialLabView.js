/**
 * Explainable AI (XAI) & Adversarial Testing Lab View Component
 * Clean, simplified XAI feature breakdown & transparency lab.
 */

import { analyzeDomStructure, analyzeVisualSimilarity, generateAdversarialMutations, predictPhishingMl } from '../engine/mlModel.js';
import { analyzeUrl } from '../engine/urlAnalyzer.js';

export function renderAdversarialLabView(container) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="brain"></i> Explainable AI (XAI) Lab
      </h2>
      <p class="view-subtitle">
        Understand why the AI classifies a threat with transparent SHAP-style feature impact weights.
      </p>
    </div>

    <!-- Quick Presets -->
    <div class="presets-bar">
      <span class="presets-label">TRY TARGET:</span>
      <button class="tab-pill xai-preset-btn" data-url="http://paypa1-security-verify.xyz/login.php">
        <i data-lucide="alert-triangle" style="width:13px; color:var(--red)"></i> Fake PayPal Typosquat
      </button>
      <button class="tab-pill xai-preset-btn" data-url="http://192.168.1.100/secure/bank.html">
        <i data-lucide="server" style="width:13px; color:var(--yellow)"></i> Raw IP Phishing Host
      </button>
      <button class="tab-pill xai-preset-btn" data-url="https://github.com/security/advisories">
        <i data-lucide="check-circle" style="width:13px; color:var(--green)"></i> Legitimate Portal
      </button>
    </div>

    <!-- Main Input Card -->
    <div class="clean-card" style="margin-bottom: 24px;">
      <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
        WEBSITE OR PHISHING URL TO EVALUATE
      </label>
      <div style="display: flex; gap: 12px; flex-wrap: wrap;">
        <input type="text" id="xaiUrlInput" class="clean-input" style="flex: 1; min-width: 260px;" value="http://paypa1-security-verify.xyz/login.php">
        <button id="runXaiBtn" class="btn-primary-clean">
          <i data-lucide="cpu"></i> Run AI Model &amp; Explain Features
        </button>
      </div>
    </div>

    <!-- Results Grid -->
    <div id="xaiResultsContainer"></div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const xaiUrlInput = container.querySelector('#xaiUrlInput');
  const runXaiBtn = container.querySelector('#runXaiBtn');
  const xaiResultsContainer = container.querySelector('#xaiResultsContainer');

  container.querySelectorAll('.xai-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      xaiUrlInput.value = btn.dataset.url;
      runXaiAnalysis();
    });
  });

  runXaiBtn.addEventListener('click', runXaiAnalysis);

  // Run initial analysis
  runXaiAnalysis();

  function runXaiAnalysis() {
    const url = xaiUrlInput.value;
    const lexicalRes = analyzeUrl(url);

    const mlRes = predictPhishingMl({
      typosquattingMatch: lexicalRes.spoofedBrand || (url.includes('paypa1') ? 'paypal' : null),
      entropy: parseFloat(lexicalRes.entropy) || 4.1,
      suspiciousDomForm: url.includes('.xyz') || url.includes('login'),
      isHighRiskTld: url.includes('.xyz') || url.includes('.top'),
      isIpHost: /^\d{1,3}\./.test(lexicalRes.hostname)
    });

    const mutations = generateAdversarialMutations(url);

    const isPhish = mlRes.prediction === 'PHISHING';
    const riskClass = isPhish ? 'danger' : mlRes.prediction === 'SUSPICIOUS' ? 'warning' : 'safe';

    xaiResultsContainer.innerHTML = `
      <div class="scanner-split-container">
        
        <!-- Left: Prediction & SHAP Breakdown -->
        <div style="display: flex; flex-direction: column; gap: 16px;">
          
          <div class="score-banner-card">
            <div>
              <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
                Machine Learning Prediction
              </span>
              <div style="margin-top: 4px;">
                <span class="risk-badge ${riskClass}">
                  ${mlRes.prediction} (${mlRes.confidence}% CONFIDENCE)
                </span>
              </div>
              <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 8px;">
                Phishing: <strong>${mlRes.probabilities.phishing}%</strong> &bull; 
                Suspicious: <strong>${mlRes.probabilities.suspicious}%</strong> &bull; 
                Safe: <strong>${mlRes.probabilities.legitimate}%</strong>
              </div>
            </div>

            <div class="score-circle-wrap ${riskClass}">
              <span class="score-number">${mlRes.probabilities.phishing}</span>
              <span class="score-sub">PHISH %</span>
            </div>
          </div>

          <!-- SHAP Feature Attribution Cards -->
          <div class="clean-card">
            <h4 class="card-heading" style="font-size: 0.9rem;">
              <i data-lucide="bar-chart-2" style="color: var(--primary);"></i> Feature Attributions (Why it got this score)
            </h4>
            
            <div style="display: flex; flex-direction: column; gap: 10px;">
              ${mlRes.xaiAttributions.length === 0 ? `
                <div style="font-size: 0.85rem; color: var(--green); padding: 8px;">No adverse risk features triggered. Domain conforms to standard patterns.</div>
              ` : mlRes.xaiAttributions.map(attr => `
                <div class="flag-card danger">
                  <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: #fff; font-size: 0.88rem;">${attr.feature}</strong>
                    <span style="color: var(--red); font-weight: 700; font-size: 0.85rem;">+${attr.impact}% Risk</span>
                  </div>
                  <div class="flag-desc">${attr.desc}</div>
                </div>
              `).join('')}
            </div>
          </div>

        </div>

        <!-- Right: Adversarial Mutation Evasion Testing -->
        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="shield-alert" style="color: var(--yellow);"></i> Adversarial Evasion Mutations
          </h4>
          <p style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 14px;">
            Simulated deceptive mutations attackers use to test if filters can be fooled:
          </p>

          <div style="display: flex; flex-direction: column; gap: 10px;">
            ${mutations.map(m => `
              <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-light); border-radius: 8px; padding: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                  <strong style="color: var(--primary); font-size: 0.82rem;">${m.type}</strong>
                  <span class="risk-badge warning" style="font-size: 0.68rem; padding: 2px 6px;">MUTATION</span>
                </div>
                <code style="display: block; font-size: 0.8rem; margin: 4px 0 6px 0; color: #fff; word-break: break-all;">${m.url}</code>
                <p style="font-size: 0.74rem; color: var(--text-muted);">${m.evasionStrategy}</p>
              </div>
            `).join('')}
          </div>
        </div>

      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
