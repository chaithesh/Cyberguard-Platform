/**
 * SMS / SMiShing Detector View Component
 * Clean, simplified SMS fraud & delivery scam scanner with visual phone preview.
 */

import { analyzeSmishing } from '../engine/smishingAnalyzer.js';

const SAMPLE_SMS = {
  usps: {
    phone: '+1 (833) 492-0199',
    text: '[USPS Alert]: Your package delivery has been placed on hold due to incomplete address details. Update immediately at: http://usps-redelivery-tracking.xyz/confirm'
  },
  bank: {
    phone: '+44 7700 900077',
    text: 'CHASE BANK ALERT: An unauthorized login attempt of $850 was made on your account. If this was not you, verify now: http://paypa1-security-verify.xyz/login.php'
  },
  legit: {
    phone: '22395',
    text: 'Your 2-Factor Security Code is 849204. Valid for 10 minutes. Do not share this code with anyone.'
  }
};

export function renderSmishingScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="message-square"></i> SMS &amp; SMiShing Scanner
      </h2>
      <p class="view-subtitle">
        Analyze text messages for fake parcel tracking, bank lockouts, shortened links, and unverified senders.
      </p>
    </div>

    <!-- Quick Presets -->
    <div class="presets-bar">
      <span class="presets-label">TRY SAMPLE:</span>
      <button class="tab-pill sms-sample-btn" data-type="usps">
        <i data-lucide="package" style="width:13px; color:var(--yellow)"></i> Fake USPS Delivery
      </button>
      <button class="tab-pill sms-sample-btn" data-type="bank">
        <i data-lucide="credit-card" style="width:13px; color:var(--red)"></i> Bank Lockout Scam
      </button>
      <button class="tab-pill sms-sample-btn" data-type="legit">
        <i data-lucide="shield-check" style="width:13px; color:var(--green)"></i> Legitimate 2FA Code
      </button>
    </div>

    <div class="scanner-split-container">
      <!-- Input Panel -->
      <div class="clean-card">
        <div style="margin-bottom: 14px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            SENDER PHONE NUMBER OR SHORTCODE
          </label>
          <input type="text" id="smsPhoneInput" class="clean-input" value="+1 (833) 492-0199">
        </div>

        <div style="margin-bottom: 16px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            SMS TEXT MESSAGE BODY
          </label>
          <textarea id="smsBodyInput" class="clean-textarea" style="height: 120px;"></textarea>
        </div>

        <button id="inspectSmsBtn" class="btn-primary-clean" style="width: 100%;">
          <i data-lucide="search"></i> Inspect SMS &amp; Calculate Risk Score
        </button>

        <!-- Risk Flags Container -->
        <div id="smsFlagsContainer" style="margin-top: 20px;"></div>
      </div>

      <!-- Phone UI Mockup -->
      <div>
        <div class="phone-mockup-wrapper">
          <div class="phone-screen">
            <div class="phone-header">
              <div class="phone-sender" id="phoneSenderDisplay">+1 (833) 492-0199</div>
              <div class="phone-sub">Text Message (SMS)</div>
            </div>
            
            <div class="phone-bubble" id="phoneMessageBubble">
              <!-- Message text inserted here -->
            </div>
            
            <div id="phoneRiskAlert" style="display:none; margin-top: auto;"></div>
          </div>
        </div>
      </div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const phoneInput = container.querySelector('#smsPhoneInput');
  const bodyInput = container.querySelector('#smsBodyInput');
  const inspectBtn = container.querySelector('#inspectSmsBtn');
  const flagsContainer = container.querySelector('#smsFlagsContainer');
  const phoneSenderDisplay = container.querySelector('#phoneSenderDisplay');
  const phoneMessageBubble = container.querySelector('#phoneMessageBubble');
  const phoneRiskAlert = container.querySelector('#phoneRiskAlert');

  loadSample('usps');

  container.querySelectorAll('.sms-sample-btn').forEach(btn => {
    btn.addEventListener('click', () => loadSample(btn.dataset.type));
  });

  inspectBtn.addEventListener('click', runSmsAnalysis);

  function loadSample(type) {
    const s = SAMPLE_SMS[type];
    if (s) {
      phoneInput.value = s.phone;
      bodyInput.value = s.text;
      runSmsAnalysis();
    }
  }

  function runSmsAnalysis() {
    const phone = phoneInput.value;
    const body = bodyInput.value;

    phoneSenderDisplay.textContent = phone || 'Unknown';
    phoneMessageBubble.textContent = body;

    const res = analyzeSmishing(phone, body);
    if (onScanComplete) onScanComplete(res);

    const riskClass = res.riskLevel.toLowerCase();

    if (res.riskLevel === 'DANGER') {
      phoneRiskAlert.style.display = 'block';
      phoneRiskAlert.innerHTML = `
        <div style="background: rgba(239,68,68,0.2); border: 1px solid var(--red); border-radius: 8px; padding: 10px; font-size: 0.78rem; color: var(--red); text-align: center; font-weight: 700;">
          ⚠️ HIGH RISK SMiShing Scam (${res.score}/100)
        </div>
      `;
    } else {
      phoneRiskAlert.style.display = 'none';
    }

    flagsContainer.innerHTML = `
      <div class="score-banner-card" style="margin-bottom: 14px; padding: 14px 16px;">
        <div>
          <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
            SMS Threat Assessment
          </span>
          <div style="margin-top: 4px;">
            <span class="risk-badge ${riskClass}">
              ${res.riskLevel} (${res.score}/100)
            </span>
          </div>
        </div>

        <div class="score-circle-wrap ${riskClass}" style="min-width: 80px; height: 80px;">
          <span class="score-number" style="font-size: 1.5rem;">${res.score}</span>
          <span class="score-sub">RISK SCORE</span>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 8px;">
        ${res.flags.length === 0 ? `
          <div style="font-size: 0.85rem; color: var(--green); padding: 8px;">No smishing keywords or suspicious links found.</div>
        ` : res.flags.map(f => `
          <div class="flag-card ${f.type === 'FAIL' ? 'danger' : ''}">
            <div class="flag-title">${f.title}</div>
            <div class="flag-desc">${f.desc}</div>
          </div>
        `).join('')}
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
