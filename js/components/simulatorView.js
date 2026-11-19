/**
 * Security Awareness "Spot the Phish" Interactive Simulation Component
 */

const PHISHING_SCENARIOS = [
  {
    id: 1,
    title: 'Bank Verification Email',
    type: 'Email',
    sender: 'security@paypa1-update.com',
    subject: 'Action Required: Your Account Has Been Locked',
    body: 'We detected unusual login attempts from Russia. Click here to confirm your credentials within 12 hours: http://paypa1-security-verify.xyz/login.php',
    isPhish: true,
    explanation: 'Contains typosquatted sender domain (paypa1-update.com), artificial time urgency (12 hours), and unencrypted .xyz lure link.'
  },
  {
    id: 2,
    title: 'Google Drive Document Sharing Alert',
    type: 'Email',
    sender: 'drive-shares-noreply@google.com',
    subject: 'Alex shared a document with you: Q4_Budget.pdf',
    body: 'Alex (alex.smith@company.com) shared a file with you on Google Drive.\n\nOpen in Docs: https://drive.google.com/file/d/1A8z9X_Example/view',
    isPhish: false,
    explanation: 'Legitimate email sent directly from google.com servers pointing strictly to official drive.google.com endpoints.'
  },
  {
    id: 3,
    title: 'SMS Package Delivery Failure',
    type: 'SMS',
    sender: '+44 7700 900077',
    subject: 'SMS Text',
    body: '[USPS Alert]: Your package delivery was stopped due to incomplete address details. Update now: http://usps-redelivery.xyz/confirm',
    isPhish: true,
    explanation: 'Delivery carriers do not send SMS alerts from foreign international mobile phone numbers asking for payment or address verification on .xyz links.'
  },
  {
    id: 4,
    title: 'HR Direct Deposit Update',
    type: 'Email',
    sender: 'hr-dept@company-internal.com',
    subject: 'Notice: Payroll Account Confirmation',
    body: 'Attached is your updated direct deposit slip: payroll_form.pdf.exe. Please double check your bank routing number.',
    isPhish: true,
    explanation: 'Classic double file extension trick (.pdf.exe). Executable file masquerading as a PDF document payload.'
  }
];

export function renderSimulatorView(container) {
  let currentIndex = 0;
  let score = 0;
  let answered = false;

  function renderScenario() {
    const s = PHISHING_SCENARIOS[currentIndex];

    container.innerHTML = `
      <div class="view-header">
        <h2 class="view-title">
          <i data-lucide="gamepad-2"></i> Spot-the-Phish Security Simulator
        </h2>
        <p class="view-subtitle">
          Test your cybersecurity skills against real-world spear phishing, SMS lures, and legitimate notifications.
        </p>
      </div>

      <!-- Score Bar -->
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;" class="glass-panel">
        <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--cyan);">
          SCENARIO ${currentIndex + 1} OF ${PHISHING_SCENARIOS.length}
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--green);">
          TOTAL SCORE: <strong>${score} / ${PHISHING_SCENARIOS.length * 100} PTS</strong>
        </div>
      </div>

      <!-- Scenario Display Panel -->
      <div class="glass-panel" style="margin-bottom: 24px;">
        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-glass); padding-bottom: 12px; margin-bottom: 16px;">
          <div>
            <span style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--text-muted);">${s.type.toUpperCase()} SENDER</span>
            <div style="font-family: var(--font-mono); color: #fff; font-weight: 600;">${s.sender}</div>
          </div>
          <span style="padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; font-family: var(--font-mono); background: rgba(0,243,255,0.1); color: var(--cyan);">
            ${s.type}
          </span>
        </div>

        <div style="margin-bottom: 16px;">
          <h3 style="font-size: 1.1rem; color: #fff; margin-bottom: 8px;">${s.subject}</h3>
          <div style="background: rgba(0,0,0,0.4); border-radius: 8px; padding: 16px; font-family: var(--font-mono); font-size: 0.88rem; color: #a5d6ff; white-space: pre-wrap; border: 1px solid rgba(255,255,255,0.08);">
            ${s.body}
          </div>
        </div>

        <!-- Decision Buttons -->
        <div style="display: flex; gap: 16px; justify-content: center; margin-top: 24px;" id="choiceButtonsContainer">
          <button id="btnMarkPhish" class="btn-primary-cyber" style="background: linear-gradient(135deg, #ff2a6d, #ff5e00); color: #fff; width: 220px; justify-content: center;">
            <i data-lucide="shield-alert"></i> THIS IS PHISHING
          </button>
          <button id="btnMarkLegit" class="btn-primary-cyber" style="background: linear-gradient(135deg, #00ff9d, #00b894); color: #000; width: 220px; justify-content: center;">
            <i data-lucide="shield-check"></i> THIS IS LEGITIMATE
          </button>
        </div>

        <!-- Feedback Result Panel -->
        <div id="feedbackBox" style="display: none; margin-top: 24px; padding: 16px; border-radius: 10px;"></div>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();

    const btnPhish = container.querySelector('#btnMarkPhish');
    const btnLegit = container.querySelector('#btnMarkLegit');
    const feedbackBox = container.querySelector('#feedbackBox');
    const choiceButtonsContainer = container.querySelector('#choiceButtonsContainer');

    btnPhish.addEventListener('click', () => handleChoice(true));
    btnLegit.addEventListener('click', () => handleChoice(false));

    function handleChoice(userSaidPhish) {
      if (answered) return;
      answered = true;

      const isCorrect = userSaidPhish === s.isPhish;
      if (isCorrect) score += 100;

      feedbackBox.style.display = 'block';
      feedbackBox.style.background = isCorrect ? 'rgba(0, 255, 157, 0.15)' : 'rgba(255, 42, 109, 0.15)';
      feedbackBox.style.border = `1px solid ${isCorrect ? 'var(--green)' : 'var(--crimson)'}`;

      feedbackBox.innerHTML = `
        <h4 style="color: ${isCorrect ? 'var(--green)' : 'var(--crimson)'}; font-family: var(--font-display); margin-bottom: 6px; display: flex; align-items: center; gap: 8px;">
          <i data-lucide="${isCorrect ? 'check-circle' : 'x-circle'}"></i>
          ${isCorrect ? 'CORRECT DIAGNOSIS! (+100 PTS)' : 'INCORRECT EVALUATION'}
        </h4>
        <p style="color: #fff; font-size: 0.85rem;"><strong>Analysis:</strong> ${s.explanation}</p>
        
        <button id="btnNextScenario" class="btn-cyber-outline" style="margin-top: 14px;">
          ${currentIndex + 1 < PHISHING_SCENARIOS.length ? 'Next Scenario →' : 'Restart Simulation 🔄'}
        </button>
      `;

      if (window.lucide) window.lucide.createIcons();

      container.querySelector('#btnNextScenario').addEventListener('click', () => {
        if (currentIndex + 1 < PHISHING_SCENARIOS.length) {
          currentIndex++;
        } else {
          currentIndex = 0;
          score = 0;
        }
        answered = false;
        renderScenario();
      });
    }
  }

  renderScenario();
}
