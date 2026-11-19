/**
 * Fake Image, Deepfake Artifact & QR Code (Quishing) Scanner View Component
 * Clean, simplified QR & Image risk detector.
 */

import { analyzeImage, analyzeQrCodePayload, generateElaCanvas } from '../engine/imageAnalyzer.js';

const SAMPLE_IMAGES = [
  {
    name: 'Deepfake ID Card Lure',
    file: { name: 'ai_midjourney_id_passport_fake.png', size: 420000 },
    type: 'ai',
    url: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=400&q=80'
  },
  {
    name: 'Edited Bank Receipt (Photoshop)',
    file: { name: 'photoshop_bank_transfer_receipt.jpg', size: 680000 },
    type: 'edited',
    url: 'https://images.unsplash.com/photo-1554224155-8d04cb21cd6c?auto=format&fit=crop&w=400&q=80'
  }
];

export function renderImageScannerView(container, onScanComplete) {
  container.innerHTML = `
    <div class="view-header">
      <h2 class="view-title">
        <i data-lucide="qr-code"></i> QR Code &amp; Image Scanner
      </h2>
      <p class="view-subtitle">
        Detect malicious QR codes (Quishing) and digital image manipulation with Error Level Analysis (ELA).
      </p>
    </div>

    <!-- Mode Selector Tabs -->
    <div class="presets-bar" style="margin-bottom: 20px;">
      <button class="tab-pill active" id="tabModeQr">
        <i data-lucide="qr-code"></i> QR Code (Quishing) Scanner
      </button>
      <button class="tab-pill" id="tabModeImage">
        <i data-lucide="image"></i> Image Tampering &amp; Deepfake
      </button>
    </div>

    <!-- QR Code Scanner Section (Default) -->
    <div id="qrScannerSection">
      <div class="clean-card" style="margin-bottom: 20px;">
        <h4 class="card-heading" style="font-size: 0.95rem;">
          <i data-lucide="shield-alert" style="color: var(--yellow);"></i> Scan QR Code Target Link
        </h4>
        <div style="display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap;">
          <img id="qrCodePreviewImg" src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=http://paypa1-security-verify.xyz/login.php" style="width: 120px; height: 120px; border-radius: 8px; border: 1px solid var(--border-light); background: #fff; padding: 4px;">
          
          <div style="flex: 1; min-width: 250px;">
            <label style="font-size: 0.8rem; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 6px;">
              DECODED QR DESTINATION URL
            </label>
            <input type="text" id="qrPayloadInput" class="clean-input" value="http://paypa1-security-verify.xyz/login.php" style="margin-bottom: 12px;">
            
            <button id="scanQrBtn" class="btn-primary-clean">
              <i data-lucide="search"></i> Inspect QR Link &amp; Calculate Risk Score
            </button>
          </div>
        </div>
      </div>

      <div id="qrResultsContainer"></div>
    </div>

    <!-- Image ELA Scanner Section (Hidden by default) -->
    <div id="imageScannerSection" style="display: none;">
      <!-- Quick Sample Buttons -->
      <div class="presets-bar">
        <span class="presets-label">TRY SAMPLE:</span>
        <button class="tab-pill img-sample-btn" data-idx="0">
          <i data-lucide="cpu" style="width:13px; color:var(--red)"></i> AI Generated ID Card
        </button>
        <button class="tab-pill img-sample-btn" data-idx="1">
          <i data-lucide="edit" style="width:13px; color:var(--yellow)"></i> Photoshop Receipt
        </button>
      </div>

      <div class="scanner-split-container">
        <!-- Canvas & Visual ELA Display -->
        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="eye" style="color: var(--primary);"></i> Image Compression Heatmap (ELA)
          </h4>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 12px;">
            <div style="text-align: center;">
              <span style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 6px;">Original Image</span>
              <img id="sourceImageDisplay" src="" style="width: 100%; height: 180px; object-fit: cover; border-radius: 8px; border: 1px solid var(--border-light);" crossOrigin="anonymous">
            </div>
            <div style="text-align: center;">
              <span style="font-size: 0.72rem; color: var(--text-muted); display: block; margin-bottom: 6px;">ELA Compression Heatmap</span>
              <canvas id="elaCanvasDisplay" style="width: 100%; height: 180px; border-radius: 8px; border: 1px solid var(--primary); background: #000;"></canvas>
            </div>
          </div>
          <p style="font-size: 0.76rem; color: var(--text-secondary); text-align: center;">
            Bright cyan/magenta glowing regions indicate digital modification or image tampering.
          </p>
        </div>

        <!-- Metadata & Results Container -->
        <div id="imageResultsContainer"></div>
      </div>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();

  const tabModeImage = container.querySelector('#tabModeImage');
  const tabModeQr = container.querySelector('#tabModeQr');
  const imageSection = container.querySelector('#imageScannerSection');
  const qrSection = container.querySelector('#qrScannerSection');

  const sourceImg = container.querySelector('#sourceImageDisplay');
  const elaCanvas = container.querySelector('#elaCanvasDisplay');
  const imageResultsContainer = container.querySelector('#imageResultsContainer');

  const qrPayloadInput = container.querySelector('#qrPayloadInput');
  const scanQrBtn = container.querySelector('#scanQrBtn');
  const qrResultsContainer = container.querySelector('#qrResultsContainer');

  // Tab switching
  tabModeQr.addEventListener('click', () => {
    tabModeQr.classList.add('active');
    tabModeImage.classList.remove('active');
    qrSection.style.display = 'block';
    imageSection.style.display = 'none';
  });

  tabModeImage.addEventListener('click', () => {
    tabModeImage.classList.add('active');
    tabModeQr.classList.remove('active');
    imageSection.style.display = 'block';
    qrSection.style.display = 'none';
    loadSampleImage(SAMPLE_IMAGES[0]);
  });

  // Preset loading for images
  container.querySelectorAll('.img-sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      loadSampleImage(SAMPLE_IMAGES[parseInt(btn.dataset.idx)]);
    });
  });

  scanQrBtn.addEventListener('click', runQrAnalysis);

  // Initial load: Run QR analysis
  runQrAnalysis();

  function runQrAnalysis() {
    const rawUrl = qrPayloadInput.value;
    const res = analyzeQrCodePayload(rawUrl);
    if (onScanComplete) onScanComplete(res);

    const riskClass = res.riskLevel.toLowerCase();

    qrResultsContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div class="score-banner-card">
          <div>
            <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
              QR Code Destination Assessment
            </span>
            <div style="margin-top: 4px;">
              <span class="risk-badge ${riskClass}">
                ${res.riskLevel} (${res.score}/100)
              </span>
            </div>
            <div style="font-size: 0.85rem; color: #fff; margin-top: 8px;">
              Target: <strong style="color: var(--primary);">${res.targetUrl}</strong>
            </div>
          </div>

          <div class="score-circle-wrap ${riskClass}">
            <span class="score-number">${res.score}</span>
            <span class="score-sub">RISK SCORE</span>
          </div>
        </div>

        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="alert-triangle" style="color: var(--yellow);"></i> Detected QR Phishing Indicators (${res.flags.length})
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

  function loadSampleImage(sample) {
    sourceImg.src = sample.url;
    sourceImg.onload = () => {
      try {
        generateElaCanvas(sourceImg, elaCanvas);
      } catch (e) {
        console.warn('Canvas ELA error:', e);
      }
      const res = analyzeImage(sample.file);
      if (onScanComplete) onScanComplete(res);
      renderImageResults(res);
    };
  }

  function renderImageResults(res) {
    const riskClass = res.riskLevel.toLowerCase();

    imageResultsContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div class="score-banner-card">
          <div>
            <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">
              Image Forensic Assessment
            </span>
            <div style="margin-top: 4px;">
              <span class="risk-badge ${riskClass}">
                ${res.riskLevel} (${res.score}/100)
              </span>
            </div>
            <div style="font-size: 0.82rem; color: #fff; margin-top: 8px;">
              Detected Software: <strong style="color: var(--primary);">${res.metadata.software}</strong>
            </div>
          </div>

          <div class="score-circle-wrap ${riskClass}">
            <span class="score-number">${res.score}</span>
            <span class="score-sub">RISK SCORE</span>
          </div>
        </div>

        <div class="clean-card">
          <h4 class="card-heading" style="font-size: 0.9rem;">
            <i data-lucide="file-text" style="color: var(--primary);"></i> Forensic Findings (${res.flags.length})
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
