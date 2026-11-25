/**
 * Fraud Phone Call (Vishing) & Reverse Caller ID Scanner View Component
 * Clean, simple caller verification & scam detector.
 * Upgraded with: Separate Country Code selector and Phone Number input.
 */

import { analyzeVishingCall, lookupCallerIdentity, saveCustomCallerIdentity } from '../engine/vishingAnalyzer.js';

const SAMPLE_CALLS = {
  irs: {
    code: '+1',
    phone: '(202) 555-0143',
    attestation: 'GATEWAY',
    transcript: 'This is Officer Davis from the Internal Revenue Service. There is an active arrest warrant issued in your name for tax fraud. Unless you resolve your balance of $2,450 immediately using Apple gift cards or Bitcoin, police will be dispatched.'
  },
  techsupport: {
    code: '+1',
    phone: '(800) 555-0188',
    attestation: 'GATEWAY',
    transcript: 'Hello, this is Windows Security Support calling. Our system flagged malware broadcasting from your computer. Please download AnyDesk remote support software immediately so our technician can clean the virus.'
  },
  otp: {
    code: '+1',
    phone: '(888) 555-0199',
    attestation: 'PARTIAL',
    transcript: 'BANK SECURITY: We detected an unauthorized transaction of $1,200. To block this transfer, read me the 6-digit one time password code we just sent to your phone.'
  },
  legit: {
    code: '+1',
    phone: '(415) 555-0122',
    attestation: 'FULL',
    transcript: 'Hello, this is an automated reminder from City Medical Center confirming your appointment tomorrow at 10:00 AM. Press 1 to confirm or call back if you need to reschedule.'
  }
};

export function renderVishingScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="phone-call"></i> Fraud Phone Call Scanner
      </h2>
      <p class="view-subtitle">
        Reverse caller ID lookup, phone scam detection, and caller risk score evaluation.
      </p>
    </div>

    <!-- Quick Call Presets -->
    <div class="presets-bar">
      <span class="presets-label">TRY SAMPLE:</span>
      <button class="tab-pill call-sample-btn" data-type="irs">
        <i data-lucide="alert-triangle" style="width:13px; color:var(--red)"></i> Fake IRS Arrest Call
      </button>
      <button class="tab-pill call-sample-btn" data-type="techsupport">
        <i data-lucide="monitor" style="width:13px; color:var(--yellow)"></i> Tech Support Remote Scam
      </button>
      <button class="tab-pill call-sample-btn" data-type="otp">
        <i data-lucide="key" style="width:13px; color:var(--red)"></i> Bank OTP Stealer Call
      </button>
      <button class="tab-pill call-sample-btn" data-type="legit">
        <i data-lucide="check-circle" style="width:13px; color:var(--green)"></i> Clinic Reminder
      </button>
    </div>

    <div class="scanner-split-container">
      <!-- Input Panel -->
      <div class="clean-card">
        <div style="margin-bottom: 14px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            CALLER PHONE NUMBER
          </label>
          <div style="display: flex; gap: 8px;">
            <select id="vishingCountryCodeSelect" class="clean-input" style="width: 140px; cursor: pointer; flex-shrink: 0;">
              <option value="+1" selected>🇺🇸 +1 (US/CA)</option>
              <option value="+91">🇮🇳 +91 (IN)</option>
              <option value="+44">🇬🇧 +44 (UK)</option>
              <option value="+61">🇦🇺 +61 (AU)</option>
              <option value="+49">🇩🇪 +49 (DE)</option>
              <option value="+33">🇫🇷 +33 (FR)</option>
              <option value="+971">🇦🇪 +971 (UAE)</option>
              <option value="+65">🇸🇬 +65 (SG)</option>
              <option value="CUSTOM">➕ Other (+XX)</option>
              <option value="NONE">Direct / None</option>
            </select>
            <input type="text" id="vishingCustomCodeInput" class="clean-input" style="width: 75px; display: none; flex-shrink: 0;" placeholder="+XX">
            <input type="text" id="vishingPhoneInput" class="clean-input" style="flex: 1;" placeholder="e.g. (202) 555-0143" value="(202) 555-0143">
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            CARRIER CALLER ID LEVEL
          </label>
          <select id="stirAttestationSelect" class="clean-input" style="cursor: pointer;">
            <option value="GATEWAY">Level C: Unverified / Gateway (High Spoof Risk)</option>
            <option value="PARTIAL">Level B: Partial Attestation (Origin Verified)</option>
            <option value="FULL">Level A: Full Attestation (Verified Identity)</option>
          </select>
        </div>

        <div style="margin-bottom: 16px;">
          <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
            CALL TRANSCRIPT OR VOICE NOTES
          </label>
          <textarea id="vishingTranscriptInput" class="clean-textarea" style="height: 100px;"></textarea>
        </div>

        <button id="inspectVishingBtn" class="btn-primary-clean" style="width: 100%;">
          <i data-lucide="search"></i> Check Caller ID &amp; Risk Score
        </button>

        <!-- Register / Whitelist Caller Identity Card (SRS [FR-VSH-03]) -->
        <div style="margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border-light);">
          <div style="display: flex; justify-content: space-between; align-items: center; cursor: pointer;" id="toggleWhitelistSection">
            <span style="font-size: 0.8rem; font-weight: 600; color: var(--primary); display: flex; align-items: center; gap: 6px;">
              <i data-lucide="user-check"></i> Register / Whitelist Caller
            </span>
            <i data-lucide="chevron-down" id="whitelistChevron" style="width: 14px; color: var(--text-muted);"></i>
          </div>

          <div id="whitelistForm" style="display: none; margin-top: 12px;">
            <div style="margin-bottom: 8px;">
              <label style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 4px;">PHONE NUMBER</label>
              <input type="text" id="whitelistPhoneInput" class="clean-input" placeholder="+1 555 123 4567" style="font-size: 0.8rem; padding: 6px 10px;">
            </div>
            <div style="margin-bottom: 8px;">
              <label style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 4px;">VERIFIED CONTACT NAME</label>
              <input type="text" id="whitelistNameInput" class="clean-input" placeholder="e.g. My Bank / Doctor Office" style="font-size: 0.8rem; padding: 6px 10px;">
            </div>
            <div style="margin-bottom: 10px;">
              <label style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 4px;">CARRIER / LINE</label>
              <input type="text" id="whitelistCarrierInput" class="clean-input" placeholder="e.g. AT&amp;T / Mobile Cellular" style="font-size: 0.8rem; padding: 6px 10px;">
            </div>
            <button id="saveWhitelistBtn" class="btn-primary-clean" style="width: 100%; font-size: 0.78rem; padding: 6px 12px; justify-content: center;">
              <i data-lucide="save"></i> Save Verified Caller
            </button>
            <div id="whitelistSuccessMsg" style="display: none; color: var(--green); font-size: 0.75rem; margin-top: 6px; text-align: center;">
              Caller saved to local verified directory!
            </div>
          </div>
        </div>
      </div>

      <!-- Results Panel -->
      <div id="vishingResultsContainer"></div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const countryCodeSelect = container.querySelector('#vishingCountryCodeSelect');
  const customCodeInput = container.querySelector('#vishingCustomCodeInput');
  const phoneInput = container.querySelector('#vishingPhoneInput');
  const attestationSelect = container.querySelector('#stirAttestationSelect');
  const transcriptInput = container.querySelector('#vishingTranscriptInput');
  const inspectBtn = container.querySelector('#inspectVishingBtn');
  const resultsContainer = container.querySelector('#vishingResultsContainer');

  const toggleBtn = container.querySelector('#toggleWhitelistSection');
  const whitelistForm = container.querySelector('#whitelistForm');
  const chevron = container.querySelector('#whitelistChevron');
  const saveBtn = container.querySelector('#saveWhitelistBtn');
  const wlPhone = container.querySelector('#whitelistPhoneInput');
  const wlName = container.querySelector('#whitelistNameInput');
  const wlCarrier = container.querySelector('#whitelistCarrierInput');
  const wlMsg = container.querySelector('#whitelistSuccessMsg');

  // Handle Country Code dropdown change
  countryCodeSelect.addEventListener('change', () => {
    if (countryCodeSelect.value === 'CUSTOM') {
      customCodeInput.style.display = 'block';
      customCodeInput.focus();
    } else {
      customCodeInput.style.display = 'none';
    }
  });

  function getFullPhoneNumber() {
    const code = countryCodeSelect.value;
    const custom = customCodeInput.value.trim();
    const rawNumber = phoneInput.value.trim();

    if (!rawNumber) return '';

    if (rawNumber.startsWith('+')) {
      return rawNumber;
    }

    if (code === 'NONE') {
      return rawNumber;
    }

    if (code === 'CUSTOM') {
      const prefix = custom.startsWith('+') ? custom : (custom ? `+${custom}` : '');
      return prefix ? `${prefix} ${rawNumber}` : rawNumber;
    }

    return `${code} ${rawNumber}`;
  }

  if (toggleBtn && whitelistForm) {
    toggleBtn.addEventListener('click', () => {
      const isHidden = whitelistForm.style.display === 'none';
      whitelistForm.style.display = isHidden ? 'block' : 'none';
      chevron.setAttribute('data-lucide', isHidden ? 'chevron-up' : 'chevron-down');
      if (window.lucide) window.lucide.createIcons();
      if (isHidden) {
        wlPhone.value = getFullPhoneNumber();
      }
    });

    saveBtn.addEventListener('click', () => {
      const p = wlPhone.value.trim();
      const n = wlName.value.trim();
      const c = wlCarrier.value.trim() || 'Mobile Cellular';
      if (!p || !n) return;

      saveCustomCallerIdentity(p, n, c);
      wlMsg.style.display = 'block';
      setTimeout(() => { if (wlMsg) wlMsg.style.display = 'none'; }, 2500);

      const fullP = getFullPhoneNumber();
      if (fullP.replace(/\D/g, '') === p.replace(/\D/g, '')) {
        runVishingAnalysis();
      }
    });
  }

  loadSample('irs');

  container.querySelectorAll('.call-sample-btn').forEach(btn => {
    btn.addEventListener('click', () => loadSample(btn.dataset.type));
  });

  inspectBtn.addEventListener('click', runVishingAnalysis);

  function loadSample(type) {
    const s = SAMPLE_CALLS[type];
    if (s) {
      countryCodeSelect.value = s.code;
      customCodeInput.style.display = 'none';
      phoneInput.value = s.phone;
      attestationSelect.value = s.attestation;
      transcriptInput.value = s.transcript;
      runVishingAnalysis();
    }
  }

  function runVishingAnalysis() {
    const phone = getFullPhoneNumber();
    const attestation = attestationSelect.value;
    const transcript = transcriptInput.value;

    const res = analyzeVishingCall(phone, transcript, attestation);
    if (onScanComplete) {
      onScanComplete({
        ...res,
        category: 'CALL',
        target: `${phone} (${res.callerIntel?.name || 'Call'})`
      });
    }

    renderResults(res);
  }

  function renderResults(res) {
    const intel = res.callerIntel;
    const riskClass = res.riskLevel.toLowerCase();

    resultsContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        
        <!-- Big Risk Score Banner -->
        <div class="score-banner-card">
          <div>
            <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
              Caller Risk Assessment
            </span>
            <div style="margin-top: 4px;">
              <span class="risk-badge ${riskClass}">
                ${res.riskLevel} (${res.score}/100)
              </span>
            </div>
            <div style="font-size: 0.85rem; color: #fff; margin-top: 8px; font-weight: 600;">
              ${intel.name} ${intel.isVerified ? '✅' : ''}
            </div>
          </div>

          <div class="score-circle-wrap ${riskClass}">
            <span class="score-number">${res.score}</span>
            <span class="score-sub">RISK SCORE</span>
          </div>
        </div>

        <!-- Caller Profile Details Card -->
        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="user-check" style="color: var(--primary);"></i> Reverse Caller Profile
          </h4>
          
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 0.82rem;">
            <div style="background: rgba(0,0,0,0.3); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-light);">
              <span style="color: var(--text-muted); display: block; font-size: 0.72rem;">COMMUNITY SPAM REPORTS</span>
              <strong style="color: ${intel.spamScore >= 50 ? 'var(--red)' : 'var(--green)'};">
                ${intel.spamScore}% Spam Risk (${intel.spamCount.toLocaleString()} Reports)
              </strong>
            </div>

            <div style="background: rgba(0,0,0,0.3); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-light);">
              <span style="color: var(--text-muted); display: block; font-size: 0.72rem;">LINE TYPE &amp; CARRIER</span>
              <strong style="color: #fff;">${intel.carrier}</strong>
            </div>

            <div style="background: rgba(0,0,0,0.3); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-light);">
              <span style="color: var(--text-muted); display: block; font-size: 0.72rem;">CATEGORY</span>
              <span style="color: #fff;">${intel.category}</span>
            </div>

            <div style="background: rgba(0,0,0,0.3); padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-light);">
              <span style="color: var(--text-muted); display: block; font-size: 0.72rem;">REPORTED LOCATION</span>
              <span style="color: #fff;">${intel.location}</span>
            </div>
          </div>
        </div>

        <!-- Detected Vishing Flags -->
        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="alert-triangle" style="color: var(--yellow);"></i> Detected Scam Indicators (${res.flags.length})
          </h4>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${res.flags.map(f => `
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
