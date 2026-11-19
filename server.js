/**
 * Lightweight HTTP Server for CyberGuard Platform
 * Run with: npm run dev
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
  filePath = path.normalize(filePath);

  // Security check: stay within PUBLIC_DIR
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════╗');
  console.log('  ║      🛡️  CyberGuard Platform Ready        ║');
  console.log('  ╠══════════════════════════════════════════╣');
  console.log(`  ║  🌐 Local:   http://localhost:${PORT}          ║`);
  console.log('  ║  📁 Serving: ' + PUBLIC_DIR.slice(-28).padEnd(28) + '  ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log('');
  console.log('  Watching for file changes... (Ctrl+C to stop)');
  console.log('');

  // Auto-open browser on first start (not on nodemon restarts)
  if (!process.env.NODEMON_RESTART) {
    const { exec } = require('child_process');
    exec(`start http://localhost:${PORT}`);
  }
});

// Signal to nodemon that this is a restart (not a fresh start)
process.on('SIGUSR2', () => {
  process.env.NODEMON_RESTART = '1';
  process.kill(process.pid, 'SIGUSR2');
});
