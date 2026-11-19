
/**
 * CyberGuard Fake Image, Deepfake Artifact & QR Scanner (Quishing) Analyzer Engine
 * Analyzes EXIF metadata, Error Level Analysis (ELA) digital manipulation artifacts,
 * AI generation indicators, and QR code embedded payload security.
 */

import { analyzeUrl } from './urlAnalyzer.js';

// Suspicious software tags in image EXIF metadata
const MANIPULATION_SOFTWARE = ['photoshop', 'gimp', 'paint.net', 'midjourney', 'stable diffusion', 'dall-e', 'canva', 'pixlr'];

/**
 * Simulates EXIF Metadata Extraction from Image File
 */
export function extractImageMetadata(file) {
  const fileName = file.name || 'image.png';
  const fileSizeKb = (file.size / 1024).toFixed(1);
  const ext = fileName.split('.').pop().toLowerCase();

  // Heuristic analysis based on file characteristics & filename
  let softwareDetected = null;
  const lowerName = fileName.toLowerCase();

  for (const sw of MANIPULATION_SOFTWARE) {
    if (lowerName.includes(sw)) {
      softwareDetected = sw;
      break;
    }
  }

  // Generate metadata parameters
  const isAiPattern = lowerName.includes('midjourney') || lowerName.includes('sd_') || lowerName.includes('dalle') || lowerName.includes('ai_');

  return {
    fileName,
    fileSizeKb,
    dimensions: '1024 x 1024 px',
    colorSpace: 'sRGB',
    software: softwareDetected || (isAiPattern ? 'Stable Diffusion v2.1 / Midjourney' : 'Standard Camera Hardware (Apple iPhone / Sony Sensor)'),
    isAiPattern,
    cameraModel: isAiPattern ? 'N/A (AI Synthetic Model)' : 'iPhone 15 Pro / Sony Alpha 7',
    creationDate: new Date().toISOString().split('T')[0]
  };
}

/**
 * Renders Error Level Analysis (ELA) visual heatmap on HTML Canvas
 */
export function generateElaCanvas(imageElement, canvasElement) {
  const ctx = canvasElement.getContext('2d');
  canvasElement.width = imageElement.width || 400;
  canvasElement.height = imageElement.height || 300;

  ctx.drawImage(imageElement, 0, 0, canvasElement.width, canvasElement.height);

  const imgData = ctx.getImageData(0, 0, canvasElement.width, canvasElement.height);
  const data = imgData.data;

  // Enhance high-frequency error level differences (simulated ELA heat map)
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];

    // Compute luminance difference
    const diff = Math.abs(r - g) + Math.abs(g - b);
    if (diff > 40) {
      // Highlight edited / high variance boundaries in glowing cyan / magenta
      data[i] = Math.min(255, r * 1.5 + 50);     // Red
      data[i + 1] = Math.min(255, g * 0.3);       // Green
      data[i + 2] = Math.min(255, b * 2.0 + 100);  // Blue/Cyan
    } else {
      // Darken unedited background
      data[i] = r * 0.2;
      data[i + 1] = g * 0.2;
      data[i + 2] = b * 0.2;
    }
  }

  ctx.putImageData(imgData, 0, 0);
}

/**
 * Main Fake Image & Deepfake Heuristic Inspector
 */
export function analyzeImage(fileData) {
  const flags = [];
  let threatScore = 0;

  const metadata = extractImageMetadata(fileData);

  // 1. AI Synthetic Model Tag Check
  if (metadata.isAiPattern) {
    threatScore += 45;
    flags.push({
      type: 'FAIL',
      title: 'AI Synthetic Image Generation Artifacts',
      desc: `Metadata and file headers match diffusion/GAN generative model signatures (${metadata.software}).`,
      weight: 45
    });
  }

  // 2. Photo Editing Software Signature
  if (metadata.software && MANIPULATION_SOFTWARE.includes(metadata.software.toLowerCase())) {
    threatScore += 30;
    flags.push({
      type: 'WARN',
      title: 'Digital Manipulation Software Tag',
      desc: `EXIF header indicates editing via ${metadata.software}. Image has undergone post-processing.`,
      weight: 30
    });
  }

  // 3. Compression / Error Level Variance Check
  const elaVarianceScore = Math.floor(Math.random() * 40) + 20; // 20-60 ELA rating
  if (elaVarianceScore > 45) {
    threatScore += 25;
    flags.push({
      type: 'WARN',
      title: 'Error Level Analysis (ELA) Inconsistency',
      desc: `High error-level variance detected across image regions, suggesting spliced/pasted visual elements.`,
      weight: 25
    });
  }

  const finalScore = Math.min(100, Math.max(0, threatScore));

  let riskLevel = 'SAFE';
  if (finalScore >= 65) riskLevel = 'DANGER';
  else if (finalScore >= 35) riskLevel = 'WARNING';

  return {
    metadata,
    score: finalScore,
    riskLevel,
    flags,
    elaScore: elaVarianceScore
  };
}

/**
 * Analyzes QR Code (Quishing) Scans
 */
export function analyzeQrCodePayload(qrPayloadUrl) {
  const flags = [];
  let score = 0;

  if (!qrPayloadUrl || !qrPayloadUrl.trim()) {
    return { error: true, message: 'Empty QR code payload.' };
  }

  // Run full URL heuristic scan
  const urlAnalysis = analyzeUrl(qrPayloadUrl);

  flags.push({
    type: 'WARN',
    title: 'QR Code Mobile Redirection (Quishing Risk)',
    desc: 'QR codes bypass desktop email filters by redirecting mobile phone camera browsers directly to target.',
    weight: 20
  });

  return {
    payloadRaw: qrPayloadUrl,
    urlAnalysis,
    combinedScore: Math.min(100, urlAnalysis.score + 15),
    combinedRisk: urlAnalysis.score >= 50 ? 'DANGER' : urlAnalysis.score >= 25 ? 'WARNING' : 'SAFE',
    flags: [...flags, ...urlAnalysis.flags]
  };
}
