import { build } from 'esbuild';
import { copyFileSync, mkdirSync, existsSync, readdirSync } from 'fs';

// Ensure dist/ exists
mkdirSync('dist', { recursive: true });

// Bundle the Service Worker
await build({
  entryPoints: ['src/background.ts'],
  bundle: true,
  outfile: 'dist/background.js',
  platform: 'browser',
  target: 'chrome110',
  // Chrome MV3 Service Workers don't support ES modules via import()
  format: 'iife',
});

// Bundle the Monitor UI
await build({
  entryPoints: ['src/monitor.ts'],
  bundle: true,
  outfile: 'dist/monitor.js',
  platform: 'browser',
  target: 'chrome110',
  format: 'iife',
});

// Copy manifest.json and UI assets into dist/
copyFileSync('manifest.json', 'dist/manifest.json');
copyFileSync('public/monitor.html', 'dist/monitor.html');
copyFileSync('src/monitor.css', 'dist/monitor.css');
copyFileSync('public/icon.png', 'dist/icon.png');

// Copy icons/ folder into dist/icons/
mkdirSync('dist/icons', { recursive: true });
for (const file of readdirSync('icons')) {
  copyFileSync(`icons/${file}`, `dist/icons/${file}`);
}

// Copy the Go Wasm runtime shim — required by the Go-compiled Wasm module.
// The service worker loads it via importScripts() before instantiating ppo.wasm.
const WASM_EXEC_SRC = '/usr/local/go/lib/wasm/wasm_exec.js';
if (existsSync(WASM_EXEC_SRC)) {
  copyFileSync(WASM_EXEC_SRC, 'dist/wasm_exec.js');
} else {
  console.warn('⚠️  wasm_exec.js not found at', WASM_EXEC_SRC);
  console.warn('   Run: cp $(go env GOROOT)/lib/wasm/wasm_exec.js dist/');
}

// Copy the compiled Wasm binary if it exists
if (existsSync('public/ppo.wasm')) {
  copyFileSync('public/ppo.wasm', 'dist/ppo.wasm');
} else {
  console.warn('⚠️  public/ppo.wasm not found — run `npm run build:wasm` first');
}

console.log('✅  Extension built → dist/');
console.log('   Load dist/ as an unpacked extension in Chrome.');
