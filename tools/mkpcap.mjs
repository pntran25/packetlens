// Writes the synthetic demo capture to fixtures/sample.pcap so users have a real
// file to open. `npm run fixtures`.
import { writeFile } from 'node:fs/promises';
import { buildSample } from '../fixtures/sample.js';

const bytes = buildSample();
await writeFile(new URL('../fixtures/sample.pcap', import.meta.url), bytes);
console.log(`Wrote fixtures/sample.pcap (${bytes.length} bytes)`);
