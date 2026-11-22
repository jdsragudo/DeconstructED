const textEncoder = new TextEncoder();

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

/**
 * Compute IEEE 802.3 CRC-32 for a byte buffer.
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function crc32(bytes) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function toBytes(content) {
  if (content instanceof Uint8Array) return content;
  if (typeof content === 'string') return textEncoder.encode(content);
  if (ArrayBuffer.isView(content)) {
    return new Uint8Array(content.buffer, content.byteOffset, content.byteLength);
  }
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  return textEncoder.encode(String(content ?? ''));
}

/**
 * Build an uncompressed (Method 0 STORE) ZIP archive in memory.
 * @param {Array<{name: string, content: string | Uint8Array}>} files
 * @returns {Uint8Array}
 */
export function createStoreZip(files) {
  const entries = [];
  let localTotal = 0;
  let cdTotal = 0;

  for (const file of files) {
    const nameBytes = textEncoder.encode(file.name);
    const dataBytes = toBytes(file.content);
    const crc = crc32(dataBytes);
    const lfhSize = 30 + nameBytes.length;
    const cdSize = 46 + nameBytes.length;

    entries.push({
      nameBytes,
      dataBytes,
      crc,
      localOffset: localTotal,
    });

    localTotal += lfhSize + dataBytes.length;
    cdTotal += cdSize;
  }

  const eocdSize = 22;
  const out = new Uint8Array(localTotal + cdTotal + eocdSize);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

  let offset = 0;
  for (const entry of entries) {
    // Local File Header (30 bytes + filename)
    view.setUint32(offset + 0, 0x04034b50, true);
    view.setUint16(offset + 4, 20, true); // version needed
    view.setUint16(offset + 6, 0x0800, true); // UTF-8 filename flag
    view.setUint16(offset + 8, 0, true); // method 0 (STORE)
    view.setUint16(offset + 10, 0x0000, true); // mod time
    view.setUint16(offset + 12, 0x5421, true); // mod date
    view.setUint32(offset + 14, entry.crc, true);
    view.setUint32(offset + 18, entry.dataBytes.length, true);
    view.setUint32(offset + 22, entry.dataBytes.length, true);
    view.setUint16(offset + 26, entry.nameBytes.length, true);
    view.setUint16(offset + 28, 0, true); // extra length
    out.set(entry.nameBytes, offset + 30);
    offset += 30 + entry.nameBytes.length;

    out.set(entry.dataBytes, offset);
    offset += entry.dataBytes.length;
  }

  const cdStart = offset;
  for (const entry of entries) {
    // Central Directory Header (46 bytes + filename)
    view.setUint32(offset + 0, 0x02014b50, true);
    view.setUint16(offset + 4, 20, true); // version made by
    view.setUint16(offset + 6, 20, true); // version needed
    view.setUint16(offset + 8, 0x0800, true); // UTF-8 flag
    view.setUint16(offset + 10, 0, true); // method 0 (STORE)
    view.setUint16(offset + 12, 0x0000, true); // mod time
    view.setUint16(offset + 14, 0x5421, true); // mod date
    view.setUint32(offset + 16, entry.crc, true);
    view.setUint32(offset + 20, entry.dataBytes.length, true);
    view.setUint32(offset + 24, entry.dataBytes.length, true);
    view.setUint16(offset + 28, entry.nameBytes.length, true);
    view.setUint16(offset + 30, 0, true); // extra length
    view.setUint16(offset + 32, 0, true); // comment length
    view.setUint16(offset + 34, 0, true); // disk number start
    view.setUint16(offset + 36, 0, true); // internal attrs
    view.setUint32(offset + 38, 0, true); // external attrs
    view.setUint32(offset + 42, entry.localOffset, true);
    out.set(entry.nameBytes, offset + 46);
    offset += 46 + entry.nameBytes.length;
  }

  // End of Central Directory (22 bytes)
  view.setUint32(offset + 0, 0x06054b50, true);
  view.setUint16(offset + 4, 0, true);
  view.setUint16(offset + 6, 0, true);
  view.setUint16(offset + 8, entries.length, true);
  view.setUint16(offset + 10, entries.length, true);
  view.setUint32(offset + 12, cdTotal, true);
  view.setUint32(offset + 16, cdStart, true);
  view.setUint16(offset + 20, 0, true);

  return out;
}

function formatMasteryPct(value) {
  const num = typeof value === 'number' && Number.isFinite(value) ? value : 0.25;
  return `${Math.round(num * 100)}%`;
}

/**
 * Construct the clean-room starter file list derived from binary X-ray evidence,
 * ML classification/risk output, and BKT mastery state.
 * @param {object} scanResult
 * @param {object} mlResult
 * @param {Record<string, number>} masteryMap
 * @returns {Array<{name: string, content: string, summary: string}>}
 */
export function buildStarterFiles(scanResult = {}, mlResult = {}, masteryMap = {}) {
  const filename = scanResult.filename || 'specimen.bin';
  const format = (scanResult.format || 'zip').toUpperCase();
  const archetype = mlResult.topArchetype || 'Productivity / Utility';
  const risk = mlResult.risk || { score: 0, level: 'LOW', attributions: [] };
  const runtimes = Array.isArray(scanResult.runtimes) && scanResult.runtimes.length
    ? scanResult.runtimes.join(', ')
    : 'Standard Runtime';
  const perms = Array.isArray(scanResult.permissions) ? scanResult.permissions : [];
  const sections = Array.isArray(scanResult.sections) ? scanResult.sections : [];
  const xapkNote = scanResult.xapk
    ? `\n- **XAPK Topology**: ${scanResult.xapk.splitApks.length} split APKs, ABIs [${scanResult.xapk.abis.join(', ') || 'none'}], ${scanResult.xapk.obbPacks.length} OBB expansions`
    : '';
  const pkgNote = scanResult.pkg
    ? `\n- **XAR Package TOC**: [${scanResult.pkg.files.join(', ') || 'none'}], Signature: ${scanResult.pkg.signed ? 'Present' : 'Unsigned'}`
    : '';

  const skills = [
    ['permission_hardening', 'Least-Privilege & Transport Hardening'],
    ['sqlite_safety', 'Parameterized SQLite Queries'],
    ['api_bounds', 'Bounded Arithmetic & Underflow Guards'],
    ['docker_hardening', 'Hardened Non-Root Containerization'],
  ];

  const masteryLines = skills.map(
    ([id, label]) => `- **${label}** (\`${id}\`): P(L) = ${formatMasteryPct(masteryMap?.[id])}`
  ).join('\n');

  const attributionLines = (risk.attributions || []).length
    ? risk.attributions.map(
        (a) => `| \`${a.feature}\` | ${a.value} | ${a.delta >= 0 ? '+' : ''}${a.delta} pts |`
      ).join('\n')
    : '| `baseline` | 0 | 0 pts |';

  const syllabus = `# DeconstructED Clean-Room MOOC Syllabus

## Target Specimen Evidence
- **Specimen**: \`${filename}\` (${format}, ${scanResult.byteLength ?? 0} bytes)
- **ML Archetype**: ${archetype}
- **Risk Score**: ${risk.score}/100 (${risk.level})
- **Detected Runtimes**: ${runtimes}
- **Permissions / Flags**: ${perms.length ? perms.join(', ') : 'None extracted'}${xapkNote}${pkgNote}

## Current BKT Mastery Profile
${masteryLines}

## 4-Module Clean-Room Curriculum
1. **Module 1 — Transport & Permission Hardening (\`permission_hardening\`)**
   Audit manifest capabilities and disable cleartext traffic in favor of TLS-only endpoints.
2. **Module 2 — Parameterized Persistence (\`sqlite_safety\`)**
   Replace interpolated query strings with bound \`?\` placeholders in \`prepare\` / \`execute\`.
3. **Module 3 — Bounded Domain Arithmetic (\`api_bounds\`)**
   Clamp state transitions with \`Math.max(0, ...)\` to prevent negative balance or counter underflow.
4. **Module 4 — Reproducible Container Hardening (\`docker_hardening\`)**
   Pin base image digests/tags, drop privileges with a non-root \`USER\`, and expose a \`HEALTHCHECK\`.
`;

  const architecture = `# Clean-Room Architecture Blueprint

Archetype: **${archetype}**
Derived purely from structural observation of \`${filename}\` (zero copied implementation code).

## 4-Layer Boundary Model

1. **UI Layer**
   - Strictly presentation and input validation; no direct SQL or OS calls.
   - Enforces explicit state labels and accessible error boundaries.
2. **Core Logic Layer**
   - Deterministic domain transitions with clamped lower bounds (\`Math.max(0, nextValue)\`).
   - Stateless service functions suitable for isolated unit verification.
3. **Data & Storage Layer**
   - Parameterized SQLite access via bound \`?\` placeholders (\`prepare(...)\` / \`execute(..., [...])\`).
   - Schema migrations isolated from request handlers.
4. **OS & Security Layer**
   - Least-privilege manifest/capability declarations; cleartext HTTP disabled.
   - Pinned container base image, non-root runtime user, and active health probe.
`;

  const highEntropySections = sections.filter((s) => s.packed || s.entropy > 7.2);
  const mitigations = [];
  if (scanResult.cleartextTraffic || risk.attributions?.some((a) => a.feature === 'cleartextHttp' && a.value)) {
    mitigations.push('- **Cleartext HTTP Enabled**: Enforce `usesCleartextTraffic="false"` and TLS 1.2+ certificate pinning.');
  }
  if (perms.some((p) => p.includes('READ_CONTACTS') || p.includes('WRITE_EXTERNAL_STORAGE'))) {
    mitigations.push('- **Over-Privileged Permissions**: Remove unneeded `READ_CONTACTS` / `WRITE_EXTERNAL_STORAGE`; adopt scoped storage.');
  }
  if (highEntropySections.length > 0) {
    mitigations.push(`- **High-Entropy Sections (${highEntropySections.map((s) => s.name).join(', ')})**: Verify reproducible builds, symbol integrity, and avoid runtime packers.`);
  }
  if (scanResult.macho?.fairplayEncrypted) {
    mitigations.push('- **Encrypted Mach-O Slice (cryptid=1)**: Conduct clean-room behavioral spec rather than binary patching.');
  }
  if (scanResult.pkg && !scanResult.pkg.signed) {
    mitigations.push('- **Unsigned XAR Installer (.pkg)**: Sign distribution archives with a pinned developer certificate and verify checksums.');
  }
  if (mitigations.length === 0) {
    mitigations.push('- **Baseline Surface Hygiene**: Maintain parameterized queries, bounded arithmetic, and pinned non-root containers.');
  }

  const threatModel = `# Threat Model — ${archetype}

Reference Specimen: \`${filename}\` (${format})
Composite Risk Score: **${risk.score}/100 (${risk.level})**

## Risk Attribution Breakdown
| Feature | Observed Value | Risk Delta |
| :--- | :--- | :--- |
${attributionLines}

## Prioritized Mitigations
${mitigations.join('\n')}
`;

  const appJs = `// Clean-room starter module generated by DeconstructED for ${archetype}
// Zero code copied from ${filename}; implements hardened baseline patterns.

/**
 * Apply a non-negative clamped delta to a numeric resource counter.
 * @param {number} current
 * @param {number} deduction
 * @returns {number}
 */
export function applyBoundedDelta(current, deduction) {
  if (!Number.isFinite(current) || !Number.isFinite(deduction) || deduction < 0) {
    throw new RangeError('Inputs must be finite non-negative numbers');
  }
  return Math.max(0, current - deduction);
}

/**
 * Execute a parameterized query descriptor using bound '?' placeholders.
 * @param {{ prepare: (sql: string) => { get: (...args: unknown[]) => unknown } }} db
 * @param {string} recordId
 * @returns {unknown}
 */
export function findRecordSafe(db, recordId) {
  const stmt = db.prepare('SELECT id, status, updated_at FROM records WHERE id = ?');
  return stmt.get(recordId);
}

/**
 * Health check response payload for container readiness probes.
 * @returns {{ ok: boolean, archetype: string }}
 */
export function getHealthStatus() {
  return { ok: true, archetype: ${JSON.stringify(archetype)} };
}
`;

  const starterTestJs = `import test from 'node:test';
import assert from 'node:assert/strict';
import { applyBoundedDelta, findRecordSafe, getHealthStatus } from '../src/app.js';

test('applyBoundedDelta clamps at zero and rejects negative deductions', () => {
  assert.equal(applyBoundedDelta(100, 35), 65);
  assert.equal(applyBoundedDelta(10, 50), 0);
  assert.throws(() => applyBoundedDelta(10, -5), RangeError);
});

test('findRecordSafe uses parameterized ? placeholder', () => {
  let capturedSql = '';
  let capturedArgs = [];
  const mockDb = {
    prepare(sql) {
      capturedSql = sql;
      return {
        get(...args) {
          capturedArgs = args;
          return { id: args[0], status: 'active' };
        },
      };
    },
  };
  const row = findRecordSafe(mockDb, 'item-42');
  assert.ok(capturedSql.includes('?'));
  assert.deepEqual(capturedArgs, ['item-42']);
  assert.equal(row.id, 'item-42');
  assert.equal(getHealthStatus().ok, true);
});
`;

  const dockerfile = `FROM node:22.14.0-alpine

WORKDIR /app
COPY --chown=node:node src ./src
COPY --chown=node:node tests ./tests

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD node -e "import('./src/app.js').then(m => process.exit(m.getHealthStatus().ok ? 0 : 1))"

CMD ["node", "--test"]
`;

  const dockerignore = `node_modules
.git
.env
*.log
dist
coverage
`;

  const renderYaml = `services:
  - type: web
    name: deconstructed-starter
    runtime: docker
    plan: free
    dockerfilePath: ./Dockerfile
    healthCheckPath: /health
    envVars:
      - key: NODE_ENV
        value: production
`;

  const ciYml = `name: Clean-Room CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22.14.0"
      - name: Run unit tests
        run: node --test
`;

  return [
    { name: 'MOOC_SYLLABUS.md', content: syllabus, summary: 'Evidence-anchored syllabus & BKT mastery report' },
    { name: 'ARCHITECTURE.md', content: architecture, summary: 'Clean-room 4-layer architecture spec' },
    { name: 'THREAT_MODEL.md', content: threatModel, summary: 'Risk attributions & mitigation matrix' },
    { name: 'src/app.js', content: appJs, summary: 'Bounded logic & parameterized SQLite starter' },
    { name: 'tests/starter.test.js', content: starterTestJs, summary: 'Clean-room node:test verification suite' },
    { name: 'Dockerfile', content: dockerfile, summary: 'Pinned base image, non-root USER, HEALTHCHECK' },
    { name: '.dockerignore', content: dockerignore, summary: 'Container build context exclusions' },
    { name: 'render.yaml', content: renderYaml, summary: 'Render IaC deployment specification' },
    { name: '.github/workflows/ci.yml', content: ciYml, summary: 'GitHub Actions automated test workflow' },
  ];
}

/**
 * Forge a clean-room production starter ZIP archive.
 * @param {object} scanResult
 * @param {object} mlResult
 * @param {Record<string, number>} masteryMap
 * @returns {Uint8Array}
 */
export function forgeStarterZip(scanResult, mlResult, masteryMap) {
  const files = buildStarterFiles(scanResult, mlResult, masteryMap);
  return createStoreZip(files.map(({ name, content }) => ({ name, content })));
}
