/**
 * Real-Time Chrome Extension Popup Simulator View Component (Feature #2)
 */

import { analyzeUrl } from '../engine/urlAnalyzer.js';

export function renderExtensionSimulatorView(container) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="chrome"></i> Real-time Chrome Extension Active Site Guard
      </h2>
      <p class="view-subtitle">
        Simulates the background Chrome Extension overlay that inspects active web pages, injects safety badges, and blocks zero-day phishing in real-time while browsing.
      </p>
    </div>

    <div class="scanner-split-container">
      <!-- Simulated Active Browser Window -->
      <div class="glass-panel" style="padding: 0; overflow: hidden; border: 2px solid var(--border-glass);">
        <!-- Chrome Window Header Bar -->
        <div style="background: #1e293b; padding: 10px 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">
          <div style="display: flex; gap: 6px;">
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #ff5f56; display: inline-block;"></span>
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #ffbd2e; display: inline-block;"></span>
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #27c93f; display: inline-block;"></span>
          </div>

          <!-- Chrome URL Omnibox -->
          <div style="flex: 1; background: #0f172a; border-radius: 20px; padding: 6px 16px; font-family: var(--font-mono); font-size: 0.82rem; color: #fff; display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <i data-lucide="lock" style="width: 12px; color: var(--crimson)" id="extLockIcon"></i>
              <span id="extOmniboxUrl">http://paypa1-security-verify.xyz/login.php</span>
            </div>
            <span style="font-size: 0.7rem; color: var(--crimson); font-weight: 700;" id="extBadgePill">⚠️ PHISHING DETECTED</span>
          </div>

          <button id="triggerExtPopupBtn" style="background: var(--cyan); border: none; border-radius: 6px; padding: 6px 12px; cursor: pointer; color: #000; font-weight: 700; font-size: 0.78rem; display: flex; align-items: center; gap: 6px;">
            <i data-lucide="shield-alert" style="width: 14px;"></i> CyberGuard Ext
          </button>
        </div>

        <!-- Web Page Content Sandbox Mockup -->
        <div style="padding: 40px; text-align: center; background: #070a12; min-height: 320px; display: flex; flex-direction: column; align-items: center; justify-content: center;" id="extWebpageSandbox">
          <div style="border: 1px dashed var(--crimson); padding: 24px; border-radius: 12px; max-width: 480px; background: rgba(255,42,109,0.08);">
            <i data-lucide="alert-triangle" style="width: 48px; height: 48px; color: var(--crimson); margin-bottom: 12px;"></i>
            <h3 style="color: var(--crimson); font-family: var(--font-display);">WARNING: DECEPTIVE WEBSITE BLOCKED</h3>
            <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 8px;">
              CyberGuard Chrome Extension intercepted a typosquatted domain attempting to harvest credentials.
            </p>
          </div>
        </div>
      </div>

      <!-- Extension Popup Simulator Overlay Box -->
      <div class="glass-panel" style="border-color: var(--cyan);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-glass); padding-bottom: 10px; margin-bottom: 14px;">
          <div style="display: flex; align-items: center; gap: 8px; font-family: var(--font-display); color: var(--cyan); font-weight: 700;">
            <i data-lucide="shield" style="width: 18px;"></i> CyberGuard Extension
          </div>
          <span style="font-size: 0.7rem; font-family: var(--font-mono); color: var(--green);">REAL-TIME GUARD ACTIVE</span>
        </div>

        <div style="margin-bottom: 14px;">
          <label style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-muted);">ACTIVE TAB URL</label>
          <input type="text" id="extTargetUrlInput" class="cyber-input" style="font-size: 0.82rem; padding: 8px 12px; margin-top: 4px;" value="http://paypa1-security-verify.xyz/login.php">
        </div>

        <button id="extSimulateBtn" class="btn-primary-cyber" style="width: 100%; margin-bottom: 16px; justify-content: center;">
          <i data-lucide="refresh-cw"></i> Simulate Tab Navigation
        </button>

        <!-- Threat Result Box -->
        <div id="extPopupResultBox"></div>
      </div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const urlInput = container.querySelector('#extTargetUrlInput');
  const simBtn = container.querySelector('#extSimulateBtn');
  const omniboxUrl = container.querySelector('#extOmniboxUrl');
  const popupResultBox = container.querySelector('#extPopupResultBox');

  simBtn.addEventListener('click', runExtSimulation);

  runExtSimulation();

  function runExtSimulation() {
    const rawUrl = urlInput.value;
    omniboxUrl.textContent = rawUrl;

    const res = analyzeUrl(rawUrl);

    popupResultBox.innerHTML = `
      <div style="padding: 14px; background: rgba(0,0,0,0.4); border-radius: 10px; border: 1px solid ${res.riskLevel === 'DANGER' ? 'var(--crimson)' : 'var(--green)'}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">SAFETY SCORE</span>
          <span class="risk-level-badge ${res.riskLevel.toLowerCase()}">${res.riskLevel} (${res.score}/100)</span>
        </div>
        <p style="font-size: 0.8rem; color: #fff; margin-bottom: 10px;">
          ${res.riskLevel === 'DANGER' ? '⚠️ High phishing threat. Automated site blocking injected.' : '✔️ Page origin verified clean.'}
        </p>
        <button class="btn-cyber-outline" style="width: 100%; font-size: 0.75rem; justify-content: center;">
          <i data-lucide="flag"></i> Report False Positive / Negative
        </button>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
