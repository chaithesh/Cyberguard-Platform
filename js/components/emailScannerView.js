/**
 * Email Inspector View Component
 * Clean, simplified email phishing & header risk detector.
 */

import { analyzeEmail } from '../engine/emailAnalyzer.js';

const SAMPLE_EMAILS = {
  bec: {
    header: `From: "CEO John Doe" <john.doe@company-executive-mail.com>\nReturn-Path: <scammer@malicious-host.xyz>\nSubject: URGENT: Wire Transfer Required Immediately\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail`,
    body: `Hi Team,\n\nI am currently in an urgent board meeting and cannot take calls. I need you to initiate an urgent wire transfer of $45,000 to our new supplier before 5 PM today.\n\nPlease process this immediately and do not discuss with anyone as this is confidential.\n\nThanks,\nJohn Doe, CEO`
  },
  payroll: {
    header: `From: "HR Payroll Department" <hr-payroll@update-portal-payroll.top>\nReturn-Path: <hr-payroll@update-portal-payroll.top>\nSubject: Action Required: Confirm Your Payroll Direct Deposit Details\nAuthentication-Results: spf=softfail; dkim=pass; dmarc=fail`,
    body: `Dear Employee,\n\nYour account has been flagged for pending payroll update. Failure to confirm your identity within 24 hours will result in your salary payment being delayed.\n\nPlease click here to restore your direct deposit preferences: http://paypa1-security-verify.xyz/login.php\n\nAlso make sure to sign and return the attached verification sheet: invoice_payroll_update.docm\n\nHR Security Team`
  },
  legit: {
    header: `From: "GitHub Security" <noreply@github.com>\nReturn-Path: <noreply@github.com>\nSubject: [GitHub] Security Advisory Notification\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass`,
    body: `Hello,\n\nA new security advisory was published for a package used in your repository. We recommend updating your dependency to version 2.4.1.\n\nView details: https://github.com/security/advisories\n\n- The GitHub Team`
  }
};

export function renderEmailScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="mail"></i> Email Phishing Scanner
      </h2>
      <p class="view-subtitle">
        Paste an email message and headers to instantly calculate its risk score and detect spoofing.
      </p>
    </div>

    <!-- Quick 1-Click Samples -->
    <div class="presets-bar">
      <span class="presets-label">TRY SAMPLE:</span>
      <button class="tab-pill sample-email-btn" data-type="bec">
        <i data-lucide="dollar-sign" style="width:13px; color:var(--red)"></i> Fake CEO Wire Scam
      </button>
      <button class="tab-pill sample-email-btn" data-type="payroll">
        <i data-lucide="alert-circle" style="width:13px; color:var(--yellow)"></i> Payroll Spear Phish
      </button>
      <button class="tab-pill sample-email-btn" data-type="legit">
        <i data-lucide="check-circle" style="width:13px; color:var(--green)"></i> Legitimate Notification
      </button>
    </div>

    <div class="scanner-split-container">
      <!-- Input Panel -->
      <div class="clean-card">
        <div style="margin-bottom: 14px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            EMAIL MESSAGE BODY
          </label>
          <textarea id="emailBodyInput" class="clean-textarea" style="height: 150px;" placeholder="Paste email content here..."></textarea>
        </div>

        <div style="margin-bottom: 16px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            OPTIONAL EMAIL HEADERS (From, Return-Path, SPF)
          </label>
          <textarea id="emailHeaderInput" class="clean-textarea" style="height: 90px; font-size: 0.8rem;" placeholder="Paste email headers (optional)..."></textarea>
        </div>

        <button id="inspectEmailBtn" class="btn-primary-clean" style="width: 100%;">
          <i data-lucide="shield-check"></i> Analyze Email &amp; Calculate Risk Score
        </button>
      </div>

      <!-- Results Panel -->
      <div id="emailResultsContainer"></div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const headerInput = container.querySelector('#emailHeaderInput');
  const bodyInput = container.querySelector('#emailBodyInput');
  const inspectBtn = container.querySelector('#inspectEmailBtn');
  const resultsContainer = container.querySelector('#emailResultsContainer');

  // Load initial sample
  loadSample('bec');

  container.querySelectorAll('.sample-email-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      loadSample(btn.dataset.type);
    });
  });

  inspectBtn.addEventListener('click', runEmailAnalysis);

  function loadSample(type) {
    const sample = SAMPLE_EMAILS[type];
    if (sample) {
      headerInput.value = sample.header;
      bodyInput.value = sample.body;
      runEmailAnalysis();
    }
  }

  function runEmailAnalysis() {
    const headerText = headerInput.value;
    const bodyText = bodyInput.value;

    const res = analyzeEmail(bodyText, headerText);
    if (onScanComplete) onScanComplete(res);

    renderResults(res);
  }

  function renderResults(res) {
    const riskClass = res.riskLevel.toLowerCase();
    const authColor = (status) => status === 'PASS' ? 'var(--green)' : status === 'FAIL' ? 'var(--red)' : 'var(--yellow)';

    resultsContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        
        <!-- Big Risk Score Banner -->
        <div class="score-banner-card">
          <div>
            <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
              Calculated Threat Assessment
            </span>
            <div style="margin-top: 4px;">
              <span class="risk-badge ${riskClass}" style="font-size: 0.85rem; padding: 4px 12px;">
                ${res.riskLevel} (${res.score}/100)
              </span>
            </div>
            <div style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 8px;">
              Sender: <strong style="color: #fff;">${res.fromEmail || 'Unknown'}</strong>
            </div>
          </div>

          <div class="score-circle-wrap ${riskClass}">
            <span class="score-number">${res.score}</span>
            <span class="score-sub">RISK SCORE</span>
          </div>
        </div>

        <!-- Authentication Status -->
        <div class="clean-card" style="padding: 14px 18px;">
          <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); margin-bottom: 8px;">
            SECURITY PROTOCOL CHECKS:
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <span style="font-size: 0.78rem; padding: 4px 10px; border-radius: 6px; background: rgba(0,0,0,0.3); border: 1px solid ${authColor(res.authentication.spfStatus)}; color: ${authColor(res.authentication.spfStatus)};">
              SPF: ${res.authentication.spfStatus}
            </span>
            <span style="font-size: 0.78rem; padding: 4px 10px; border-radius: 6px; background: rgba(0,0,0,0.3); border: 1px solid ${authColor(res.authentication.dkimStatus)}; color: ${authColor(res.authentication.dkimStatus)};">
              DKIM: ${res.authentication.dkimStatus}
            </span>
            <span style="font-size: 0.78rem; padding: 4px 10px; border-radius: 6px; background: rgba(0,0,0,0.3); border: 1px solid ${authColor(res.authentication.dmarcStatus)}; color: ${authColor(res.authentication.dmarcStatus)};">
              DMARC: ${res.authentication.dmarcStatus}
            </span>
          </div>
        </div>

        <!-- Detected Reasons / Flags -->
        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="alert-triangle" style="color: var(--yellow);"></i> Detected Risk Indicators (${res.flags.length})
          </h4>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${res.flags.length === 0 ? `
              <div style="font-size: 0.85rem; color: var(--green); padding: 8px;">No suspicious threats or coercive psychological phrases detected.</div>
            ` : res.flags.map(f => `
              <div class="flag-card ${f.type === 'FAIL' ? 'danger' : ''}">
                <div class="flag-title">${f.title}</div>
                <div class="flag-desc">${f.desc}</div>
              </div>
            `).join('')}
          </div>
        </div>

      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  }
}
