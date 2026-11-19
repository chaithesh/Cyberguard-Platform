/**
 * Risk Scores & Overview View Component
 * Clean, simplified metrics, charts, and scan history.
 */

import { getScanHistory, clearScanHistory } from '../engine/historyStore.js';

export function renderDashboardView(container) {
  const history = getScanHistory();

  const totalScans = history.length;
  const dangerCount = history.filter(h => h.riskLevel === 'DANGER').length;
  const warningCount = history.filter(h => h.riskLevel === 'WARNING').length;
  const safeCount = history.filter(h => h.riskLevel === 'SAFE').length;

  container.innerHTML = `
    <div class="view-header">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div>
          <h2 class="view-title">
            <i data-lucide="bar-chart-3"></i> Risk Scores &amp; Overview
          </h2>
          <p class="view-subtitle">
            Summary of all scans, threat levels, and real-time detection risk scores.
          </p>
        </div>
        <div>
          <button id="clearHistoryBtn" class="btn-secondary-clean" title="Clear All History">
            <i data-lucide="trash-2"></i> Clear History
          </button>
        </div>
      </div>
    </div>

    <!-- 4 Clean Metric Cards -->
    <div class="metrics-grid">
      <div class="metric-card card-cyan">
        <span class="metric-label">TOTAL SCANS</span>
        <div class="metric-value">${totalScans}</div>
        <span class="metric-desc">Across all modules</span>
      </div>

      <div class="metric-card card-red">
        <span class="metric-label">CRITICAL DANGER (70-100)</span>
        <div class="metric-value text-red">${dangerCount}</div>
        <span class="metric-desc">High risk threats detected</span>
      </div>

      <div class="metric-card card-yellow">
        <span class="metric-label">WARNING SUSPICIOUS (35-69)</span>
        <div class="metric-value text-yellow">${warningCount}</div>
        <span class="metric-desc">Potential threats flagged</span>
      </div>

      <div class="metric-card card-green">
        <span class="metric-label">SAFE &amp; VERIFIED (0-34)</span>
        <div class="metric-value text-green">${safeCount}</div>
        <span class="metric-desc">Legitimate communications</span>
      </div>
    </div>

    <!-- Chart & Summary Split -->
    <div class="scanner-split-container" style="margin-bottom: 24px;">
      
      <!-- Risk Score Distribution Chart -->
      <div class="clean-card">
        <h3 class="card-heading">
          <i data-lucide="pie-chart" style="color: var(--primary);"></i> Risk Distribution Breakdown
        </h3>
        <div style="height: 220px; position: relative;">
          <canvas id="threatDistributionChart"></canvas>
        </div>
      </div>

      <!-- Quick Scan Score Legend -->
      <div class="clean-card">
        <h3 class="card-heading">
          <i data-lucide="shield" style="color: var(--green);"></i> How Risk Scores Work
        </h3>
        <div class="risk-explanation-list">
          <div class="risk-legend-item">
            <span class="risk-badge danger">DANGER (70 - 100)</span>
            <p>High probability of credential theft, spoofed sender, or financial fraud. Immediate blocking recommended.</p>
          </div>
          <div class="risk-legend-item">
            <span class="risk-badge warning">WARNING (35 - 69)</span>
            <p>Suspicious signals found (unverified sender, urgent urgency, or hidden links). Manual caution advised.</p>
          </div>
          <div class="risk-legend-item">
            <span class="risk-badge safe">SAFE (0 - 34)</span>
            <p>Verified authentic headers, legitimate sender identity, and clean payload structure.</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Recent Detection History Table -->
    <div class="clean-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h3 class="card-heading" style="margin-bottom: 0;">
          <i data-lucide="history" style="color: var(--primary);"></i> Recent Detection History (${history.length})
        </h3>
      </div>

      <div class="table-responsive">
        <table class="clean-table">
          <thead>
            <tr>
              <th>CATEGORY</th>
              <th>TARGET / DESCRIPTION</th>
              <th>DATE &amp; TIME</th>
              <th>RISK SCORE</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            ${history.length === 0 ? `
              <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No scans recorded yet. Try scanning an Email, SMS, Call, or QR code!</td></tr>
            ` : history.map(h => `
              <tr>
                <td><span class="category-pill">${h.category}</span></td>
                <td style="font-weight: 500; color: #fff;">${h.target}</td>
                <td style="color: var(--text-muted); font-size: 0.8rem;">${h.timestamp}</td>
                <td>
                  <strong style="color: ${h.riskLevel === 'DANGER' ? 'var(--red)' : h.riskLevel === 'WARNING' ? 'var(--yellow)' : 'var(--green)'}; font-size: 1rem;">
                    ${h.score} / 100
                  </strong>
                </td>
                <td>
                  <span class="risk-badge ${h.riskLevel.toLowerCase()}">
                    ${h.riskLevel}
                  </span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const clearHistoryBtn = container.querySelector('#clearHistoryBtn');
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      clearScanHistory();
      renderDashboardView(container);
    });
  }

  // Render Risk Distribution Chart
  renderRiskChart(dangerCount, warningCount, safeCount);
}

function renderRiskChart(danger, warning, safe) {
  if (typeof Chart === 'undefined') return;

  const ctxPie = document.getElementById('threatDistributionChart');
  if (ctxPie) {
    new Chart(ctxPie, {
      type: 'doughnut',
      data: {
        labels: ['High Risk (Danger)', 'Suspicious (Warning)', 'Safe (Clean)'],
        datasets: [{
          data: [danger || 0, warning || 0, safe || 0],
          backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
          borderColor: '#1e293b',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 } }
          }
        }
      }
    });
  }
}
