/**
 * CyberGuard Main Application Entry Point & Navigation Router
 * Simplified, focused, multi-vector threat scanner
 */

import { renderDashboardView } from './components/dashboardView.js';
import { renderUrlScannerView } from './components/urlScannerView.js';
import { renderEmailScannerView } from './components/emailScannerView.js';
import { renderSmishingScannerView } from './components/smishingScannerView.js';
import { renderVishingScannerView } from './components/vishingScannerView.js';
import { renderImageScannerView } from './components/imageScannerView.js';
import { renderAdversarialLabView } from './components/adversarialLabView.js';

import { saveScanRecord } from './engine/historyStore.js';

let totalScansPerformed = 0;

document.addEventListener('DOMContentLoaded', () => {
  const mainContent = document.getElementById('mainContent');
  const navBtns = document.querySelectorAll('.nav-btn');
  const scanCountBadge = document.getElementById('scannedCountBadge');

  // Simple, focused route map
  const routes = {
    'risk-scores': (container) => renderDashboardView(container),
    'dashboard': (container) => renderDashboardView(container),
    'url-scanner': (container) => renderUrlScannerView(container, handleScanComplete),
    'email-scanner': (container) => renderEmailScannerView(container, handleScanComplete),
    'smishing-scanner': (container) => renderSmishingScannerView(container, handleScanComplete),
    'vishing-scanner': (container) => renderVishingScannerView(container, handleScanComplete),
    'image-scanner': (container) => renderImageScannerView(container, handleScanComplete),
    'adversarial-lab': (container) => renderAdversarialLabView(container)
  };

  // Switch View Tab
  function switchTab(tabId) {
    navBtns.forEach(btn => {
      if (btn.dataset.tab === tabId) btn.classList.add('active');
      else btn.classList.remove('active');
    });

    if (routes[tabId]) {
      mainContent.innerHTML = '';
      routes[tabId](mainContent);
      if (window.lucide) window.lucide.createIcons();
    }
  }

  // Bind Navigation Clicks
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });

  function handleScanComplete(scanData) {
    totalScansPerformed++;
    if (scanCountBadge) {
      scanCountBadge.innerHTML = `<i data-lucide="activity"></i> Scans: <strong>${totalScansPerformed}</strong>`;
      if (window.lucide) window.lucide.createIcons();
    }

    saveScanRecord(scanData);
  }

  // Load default tab (Risk Scores Overview)
  switchTab('risk-scores');
});
