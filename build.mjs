// Bundles PacketLens into a single self-contained dist/index.html (inlined JS + CSS
// + the worker as a blob), so it can be opened from disk or hosted anywhere.
import { build } from 'esbuild';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';

await rm('dist', { recursive: true, force: true });
await mkdir('dist', { recursive: true });

// Bundle the worker first (it is loaded via new Worker(new URL(...))).
const workerBundle = await build({
  entryPoints: ['src/ui/worker.js'],
  bundle: true, format: 'esm', write: false, minify: true, target: 'es2020',
});
const workerCode = workerBundle.outputFiles[0].text;

// Bundle the main app, replacing the Worker URL construction with a blob URL.
const shim = `
const __workerCode = ${JSON.stringify(workerCode)};
const __workerUrl = URL.createObjectURL(new Blob([__workerCode], { type: 'text/javascript' }));
`;

const appBundle = await build({
  entryPoints: ['src/ui/app.js'],
  bundle: true, format: 'esm', write: false, minify: true, target: 'es2020',
  define: { 'import.meta.url': '"packetlens://app"' },
  plugins: [{
    name: 'worker-url',
    setup(b) {
      // Replace `new Worker(new URL('./worker.js', import.meta.url), ...)` at runtime.
    },
  }],
});
let appCode = appBundle.outputFiles[0].text;
// Swap the Worker construction to use the inlined blob.
appCode = appCode.replace(/new Worker\(new URL\([^)]*\)\s*,\s*\{[^}]*\}\)/g, 'new Worker(__workerUrl,{type:"module"})');
appCode = appCode.replace(/new Worker\(new URL\([^)]*\)\)/g, 'new Worker(__workerUrl,{type:"module"})');

const css = await readFile('src/ui/styles.css', 'utf8');
let html = await readFile('index.html', 'utf8');
html = html.replace('<link rel="stylesheet" href="src/ui/styles.css">', `<style>${css}</style>`);
html = html.replace('<script type="module" src="src/ui/app.js"></script>', `<script type="module">${shim}\n${appCode}</script>`);

await writeFile('dist/index.html', html);
const size = Buffer.byteLength(html);
console.log(`Built dist/index.html (${(size / 1024).toFixed(0)} KB) — single self-contained file.`);
