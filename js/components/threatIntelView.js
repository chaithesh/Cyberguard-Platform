/**
 * Threat Intelligence Database & YARA Rule Sandbox Component
 */

import { DEFAULT_YARA_RULES, evaluateYaraRules, KNOWN_IOC_DATABASE } from '../engine/yaraEngine.js';

export function renderThreatIntelView(container) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="database"></i> Threat Intelligence & YARA Rule Sandbox
      </h2>
      <p class="view-subtitle">
        Search live Indicators of Compromise (IoCs) or compile custom YARA threat hunting rules against raw payload samples.
      </p>
    </div>

    <div class="tab-row">
      <button class="tab-pill active" id="tabThreatIoc"><i data-lucide="shield-search"></i> IoC Indicator Database</button>
      <button class="tab-pill" id="tabYaraSandbox"><i data-lucide="code"></i> YARA Rule Test bench</button>
    </div>

    <!-- IoC Database Panel -->
    <div id="iocSection">
      <div class="glass-panel" style="margin-bottom: 20px;">
        <div class="cyber-input-group">
          <i data-lucide="search" class="input-icon"></i>
          <input type="text" id="iocSearchInput" class="cyber-input" placeholder="Search hash, domain, IP address, or threat category...">
        </div>
      </div>

      <div class="glass-panel" style="padding: 0; overflow: hidden;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem;">
          <thead>
            <tr style="background: rgba(0,243,255,0.08); border-bottom: 1px solid var(--border-glass); font-family: var(--font-mono); color: var(--cyan);">
              <th style="padding: 14px;">TYPE</th>
              <th style="padding: 14px;">INDICATOR VALUE</th>
              <th style="padding: 14px;">CATEGORY</th>
              <th style="padding: 14px;">SEVERITY</th>
              <th style="padding: 14px;">DATE DETECTED</th>
            </tr>
          </thead>
          <tbody id="iocTableBody">
            <!-- Rendered by JS -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- YARA Sandbox Panel -->
    <div id="yaraSection" style="display: none;">
      <div class="scanner-split-container">
        <div class="glass-panel">
          <label style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--cyan); display: block; margin-bottom: 8px;">
            YARA THREAT SIGNATURE DEFINITIONS
          </label>
          <textarea id="yaraRulesCode" class="yara-editor">${DEFAULT_YARA_RULES}</textarea>

          <label style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--cyan); display: block; margin-top: 16px; margin-bottom: 8px;">
            TARGET PAYLOAD TEXT TO EVALUATE
          </label>
          <textarea id="yaraPayloadText" class="yara-editor" style="height: 100px; color: #fff;">From: ceo@company-executive-mail.com\nSubject: URGENT: verify account access via .xyz link immediately before invoice autoopen</textarea>

          <button id="runYaraBtn" class="btn-primary-cyber" style="margin-top: 16px; width: 100%;">
            <i data-lucide="play"></i> Compile & Execute YARA Rules
          </button>
        </div>

        <div class="glass-panel">
          <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
            <i data-lucide="terminal" style="color: var(--green)"></i> YARA Execution Console Results
          </h4>
          <div id="yaraConsoleResults" style="font-family: var(--font-mono); font-size: 0.82rem; display: flex; flex-direction: column; gap: 10px;">
            <!-- Output -->
          </div>
        </div>
      </div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const tabIoc = container.querySelector('#tabThreatIoc');
  const tabYara = container.querySelector('#tabYaraSandbox');
  const iocSection = container.querySelector('#iocSection');
  const yaraSection = container.querySelector('#yaraSection');
  const tableBody = container.querySelector('#iocTableBody');
  const searchInput = container.querySelector('#iocSearchInput');

  const yaraRulesCode = container.querySelector('#yaraRulesCode');
  const yaraPayloadText = container.querySelector('#yaraPayloadText');
  const runYaraBtn = container.querySelector('#runYaraBtn');
  const yaraConsoleResults = container.querySelector('#yaraConsoleResults');

  tabIoc.addEventListener('click', () => {
    tabIoc.classList.add('active');
    tabYara.classList.remove('active');
    iocSection.style.display = 'block';
    yaraSection.style.display = 'none';
  });

  tabYara.addEventListener('click', () => {
    tabYara.classList.add('active');
    tabIoc.classList.remove('active');
    yaraSection.style.display = 'block';
    iocSection.style.display = 'none';
    runYaraEvaluation();
  });

  renderIocTable(KNOWN_IOC_DATABASE);

  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase();
    const filtered = KNOWN_IOC_DATABASE.filter(ioc => 
      ioc.value.toLowerCase().includes(q) ||
      ioc.category.toLowerCase().includes(q) ||
      ioc.type.toLowerCase().includes(q)
    );
    renderIocTable(filtered);
  });

  runYaraBtn.addEventListener('click', runYaraEvaluation);

  function renderIocTable(iocs) {
    tableBody.innerHTML = iocs.map(ioc => `
      <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(0,243,255,0.05)'" onmouseout="this.style.background='transparent'">
        <td style="padding: 12px 14px; font-family: var(--font-mono); color: var(--cyan);">${ioc.type}</td>
        <td style="padding: 12px 14px; font-family: var(--font-mono); color: #fff;">${ioc.value}</td>
        <td style="padding: 12px 14px; color: var(--text-secondary);">${ioc.category}</td>
        <td style="padding: 12px 14px;">
          <span style="padding: 4px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; background: ${ioc.risk === 'CRITICAL' ? 'rgba(255,42,109,0.2)' : 'rgba(255,183,3,0.2)'}; color: ${ioc.risk === 'CRITICAL' ? 'var(--crimson)' : 'var(--amber)'}">
            ${ioc.risk}
          </span>
        </td>
        <td style="padding: 12px 14px; font-family: var(--font-mono); color: var(--text-muted);">${ioc.added}</td>
      </tr>
    `).join('');
  }

  function runYaraEvaluation() {
    const rules = yaraRulesCode.value;
    const payload = yaraPayloadText.value;

    const results = evaluateYaraRules(rules, payload);

    yaraConsoleResults.innerHTML = results.map(r => `
      <div style="padding: 12px; background: rgba(5,10,20,0.8); border: 1px solid ${r.isMatched ? 'var(--crimson)' : 'var(--border-glass)'}; border-radius: 8px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="color: ${r.isMatched ? 'var(--crimson)' : 'var(--green)'}; font-size: 0.9rem;">
            ${r.isMatched ? '❌ RULE MATCHED:' : '✔️ RULE PASSED:'} ${r.ruleName}
          </strong>
          <span style="font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.1); color: var(--cyan);">${r.severity}</span>
        </div>
        <p style="color: var(--text-secondary); font-size: 0.78rem; margin-top: 4px;">${r.description}</p>
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">
          Matched Strings: ${r.matchedVars.length > 0 ? r.matchedVars.join(', ') : 'None'}
        </div>
      </div>
    `).join('');
  }
}
