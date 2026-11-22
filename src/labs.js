import { getStore } from './ml.js';

export const LEDGER_KEY = 'deconstructed_ledger_v1';
export const GENESIS_HASH = '0'.repeat(64);

export const LAB_ORDER = [
  'permission_hardening',
  'sqlite_safety',
  'api_bounds',
  'docker_hardening',
];

export const LAB_META = {
  permission_hardening: {
    id: 'permission_hardening',
    title: 'Permission & Transport Hardening',
    shortLabel: 'Permissions',
    prereqs: [],
  },
  sqlite_safety: {
    id: 'sqlite_safety',
    title: 'Parameterized SQLite Safety',
    shortLabel: 'SQLite Safety',
    prereqs: ['permission_hardening'],
  },
  api_bounds: {
    id: 'api_bounds',
    title: 'Bounded Domain Arithmetic',
    shortLabel: 'API Bounds',
    prereqs: ['permission_hardening'],
  },
  docker_hardening: {
    id: 'docker_hardening',
    title: 'Hardened Container Spec',
    shortLabel: 'Docker Hardening',
    prereqs: ['sqlite_safety', 'api_bounds'],
  },
};

function verifySqliteSafety(code) {
  const src = String(code || '');
  const hasInterpolation =
    /\bf["']/.test(src) ||
    /\$\{/.test(src) ||
    /["'`][^"'`]*["'`]\s*\+|\+\s*["'`]/.test(src);

  const hasExecuteTupleOrArray = /\bexecute\s*\(\s*[^,]+,\s*(\([^)]*\)|\[[^\]]*\])\s*\)/.test(src);
  const hasPrepare = /\bprepare\s*\(/.test(src);
  const hasPlaceholder = /\?/.test(src);

  const ruleDiff = [
    {
      rule: 'No string interpolation or concatenation (f", +, ${)',
      status: hasInterpolation ? 'fail' : 'pass',
      detail: hasInterpolation ? 'Detected SQL string interpolation/concatenation.' : 'Clean: no dynamic SQL string building.',
    },
    {
      rule: 'Bound ? placeholder inside execute(..., (...)) or prepare(...)',
      status: (hasPlaceholder && (hasExecuteTupleOrArray || hasPrepare)) ? 'pass' : 'fail',
      detail: (hasPlaceholder && (hasExecuteTupleOrArray || hasPrepare))
        ? 'Found parameterized ? placeholder with execute/prepare.'
        : 'Missing ? placeholder inside execute(..., (...)) or prepare(...).',
    },
  ];

  const passed = !hasInterpolation && hasPlaceholder && (hasExecuteTupleOrArray || hasPrepare);
  return {
    passed,
    ruleDiff,
    feedback: passed
      ? 'Passed: query uses bound ? placeholders without string interpolation.'
      : 'Failed: eliminate f"/+/${ interpolation and bind parameters with ? in execute(..., (...)) or prepare(...).',
  };
}

function verifyApiBounds(code) {
  const src = String(code || '');
  const hasLowerClamp = /\b(?:Math\.max|max)\s*\(\s*0\s*,/.test(src);

  // Strip Math.max(0, ...) / max(0, ...) expressions and check if raw subtraction remains in logic
  const stripped = src.replace(/\b(?:Math\.max|max)\s*\(\s*0\s*,[^)]*\)/g, '0');
  const hasUnclampedSub = /[a-zA-Z0-9_)\]]\s*-\s*[a-zA-Z0-9_(\[]/.test(
    stripped.replace(/\/\/.*$/gm, '').replace(/#.*$/gm, '')
  );

  const ruleDiff = [
    {
      rule: 'Lower-bound clamp present (Math.max(0, or max(0,)',
      status: hasLowerClamp ? 'pass' : 'fail',
      detail: hasLowerClamp ? 'Detected lower-bound clamp at 0.' : 'Missing Math.max(0, ...) or max(0, ...) clamp.',
    },
    {
      rule: 'No unclamped subtraction outside clamp',
      status: hasUnclampedSub ? 'fail' : 'pass',
      detail: hasUnclampedSub ? 'Found unclamped subtraction that can underflow below 0.' : 'All subtractions are guarded.',
    },
  ];

  const passed = hasLowerClamp && !hasUnclampedSub;
  return {
    passed,
    ruleDiff,
    feedback: passed
      ? 'Passed: subtraction is clamped with a zero lower bound.'
      : 'Failed: wrap subtraction inside Math.max(0, ...) or max(0, ...) to prevent underflow.',
  };
}

function verifyPermissionHardening(code) {
  const src = String(code || '');
  const cleartextTrue = /usesCleartextTraffic\s*=\s*["']?true["']?/i.test(src);
  const cleartextFalse = /usesCleartextTraffic\s*=\s*["']?false["']?/i.test(src);
  const hasContacts = /\bREAD_CONTACTS\b/.test(src);
  const hasExtStorage = /\bWRITE_EXTERNAL_STORAGE\b/.test(src);
  const hasScopedPerm = /android\.permission\./.test(src) || /uses-permission/i.test(src);

  const ruleDiff = [
    {
      rule: 'Disable cleartext HTTP (usesCleartextTraffic="false")',
      status: (cleartextFalse && !cleartextTrue) ? 'pass' : 'fail',
      detail: (cleartextFalse && !cleartextTrue)
        ? 'Cleartext traffic explicitly disabled.'
        : 'Must set usesCleartextTraffic="false" (never "true").',
    },
    {
      rule: 'Remove unneeded READ_CONTACTS and WRITE_EXTERNAL_STORAGE',
      status: (!hasContacts && !hasExtStorage && hasScopedPerm) ? 'pass' : 'fail',
      detail: (hasContacts || hasExtStorage)
        ? 'Over-privileged READ_CONTACTS or WRITE_EXTERNAL_STORAGE still present.'
        : (hasScopedPerm ? 'Minimal scoped permissions declared.' : 'Declare minimal scoped permissions.'),
    },
  ];

  const passed = cleartextFalse && !cleartextTrue && !hasContacts && !hasExtStorage && hasScopedPerm;
  return {
    passed,
    ruleDiff,
    feedback: passed
      ? 'Passed: cleartext traffic disabled and over-privileged permissions removed.'
      : 'Failed: set usesCleartextTraffic="false" and strip READ_CONTACTS / WRITE_EXTERNAL_STORAGE.',
  };
}

function verifyDockerHardening(code) {
  const src = String(code || '');
  const fromMatch = src.match(/^\s*FROM\s+([^\s#]+)/im);
  const imageRef = fromMatch ? fromMatch[1] : '';
  const usesLatest = /:latest$/i.test(imageRef);
  const hasPinnedTag = Boolean(imageRef) && /:[^\s:]+$/.test(imageRef) && !usesLatest;

  const userMatches = Array.from(src.matchAll(/^\s*USER\s+([^\s#]+)/gim)).map((m) => m[1]);
  const lastUser = userMatches.length ? userMatches[userMatches.length - 1] : '';
  const hasNonRootUser = Boolean(lastUser) && !/^(root|0(:0)?)$/i.test(lastUser);

  const hasHealthcheck = /^\s*HEALTHCHECK\s+/im.test(src);

  const ruleDiff = [
    {
      rule: 'Pinned base image tag (never :latest)',
      status: hasPinnedTag ? 'pass' : 'fail',
      detail: hasPinnedTag
        ? `Pinned image: ${imageRef}`
        : (usesLatest ? `Disallowed :latest tag on ${imageRef}` : 'Specify a pinned image tag (e.g. node:22.14.0-alpine).'),
    },
    {
      rule: 'Non-root USER instruction',
      status: hasNonRootUser ? 'pass' : 'fail',
      detail: hasNonRootUser ? `Running as non-root user "${lastUser}".` : 'Missing non-root USER directive.',
    },
    {
      rule: 'HEALTHCHECK probe configured',
      status: hasHealthcheck ? 'pass' : 'fail',
      detail: hasHealthcheck ? 'HEALTHCHECK instruction present.' : 'Missing HEALTHCHECK instruction.',
    },
  ];

  const passed = hasPinnedTag && hasNonRootUser && hasHealthcheck;
  return {
    passed,
    ruleDiff,
    feedback: passed
      ? 'Passed: pinned base image, non-root USER, and HEALTHCHECK verified.'
      : 'Failed: pin image tag (no :latest), add non-root USER, and define HEALTHCHECK.',
  };
}

const VERIFIERS = {
  sqlite_safety: verifySqliteSafety,
  api_bounds: verifyApiBounds,
  permission_hardening: verifyPermissionHardening,
  docker_hardening: verifyDockerHardening,
};

/**
 * Deterministically verify a lab code snippet without eval or Workers.
 * @param {string} labId
 * @param {string} code
 */
export function verifyLab(labId, code) {
  const fn = VERIFIERS[labId];
  if (!fn) {
    throw new Error(`Unknown lab: ${labId}`);
  }
  return fn(code);
}

/**
 * Compose 4 evidence-anchored labs from (scanResult x mlResult.topArchetype).
 * @param {object} scanResult
 * @param {object} mlResult
 */
export function composeLabs(scanResult = {}, mlResult = {}) {
  const filename = scanResult.filename || 'artifact.bin';
  const format = (scanResult.format || 'zip').toUpperCase();
  const archetype = mlResult.topArchetype || 'Productivity / Utility';
  const perms = Array.isArray(scanResult.permissions) ? scanResult.permissions : [];
  const schemas = scanResult.zip?.schemas || [];
  const manifests = scanResult.zip?.manifests || [];
  const sections = scanResult.sections || [];
  const packed = sections.filter((s) => s.packed);

  const permEvidence = perms.length
    ? `Scanned ${filename} (${format}) declared [${perms.join(', ')}] with usesCleartextTraffic=${Boolean(scanResult.cleartextTraffic)}.`
    : scanResult.pkg
      ? `Scanned ${filename} (${format}) XAR TOC [${scanResult.pkg.files.join(', ')}] (signed=${scanResult.pkg.signed}); enforce signed manifests and least-privilege defaults.`
      : `Scanned ${filename} (${format}) for ${archetype}: enforce least-privilege manifest capabilities and TLS-only transport.`;

  const sqlEvidence = schemas.length
    ? `Scanned ${filename} (${format}) exposed persistence schemas [${schemas.join(', ')}] in a ${archetype} context.`
    : `Scanned ${filename} (${format}) (${archetype}) references structured state queries that must avoid string interpolation.`;

  const boundsEvidence = packed.length
    ? `Scanned ${filename} (${format}) has packed section ${packed[0].name} (${packed[0].entropy.toFixed(2)} bits/byte); guard ${archetype} counters against underflow.`
    : `In ${archetype} workflows derived from ${filename}, unguarded subtractions can drive balances, quotas, or telemetry counters negative.`;

  const dockerEvidence = manifests.includes('Dockerfile')
    ? `Scanned ${filename} (${format}) includes a Dockerfile manifest; pin base tags, drop root privileges, and add HEALTHCHECK.`
    : `Packaging a clean-room ${archetype} replacement for ${filename} requires a pinned non-root Dockerfile with HEALTHCHECK.`;

  return [
    {
      ...LAB_META.permission_hardening,
      evidenceNote: permEvidence,
      prompt: `Harden the ${archetype} manifest from ${filename}: set usesCleartextTraffic="false" and keep only minimal scoped permissions (no READ_CONTACTS or WRITE_EXTERNAL_STORAGE).`,
      starterCode: `<application android:usesCleartextTraffic="true">\n  <uses-permission android:name="android.permission.INTERNET" />\n  <uses-permission android:name="android.permission.READ_CONTACTS" />\n  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />\n</application>`,
      verify: (code) => verifyLab('permission_hardening', code),
    },
    {
      ...LAB_META.sqlite_safety,
      evidenceNote: sqlEvidence,
      prompt: `Refactor the ${archetype} query from ${filename} to use a ? placeholder in execute(..., (...)) or prepare(...) with zero string interpolation.`,
      starterCode: `function lookupRecord(db, accountId) {\n  const sql = "SELECT id, balance FROM accounts WHERE id = " + accountId;\n  return db.prepare(sql).get();\n}`,
      verify: (code) => verifyLab('sqlite_safety', code),
    },
    {
      ...LAB_META.api_bounds,
      evidenceNote: boundsEvidence,
      prompt: `Clamp the ${archetype} state transition derived from ${filename} with Math.max(0, ...) or max(0, ...) so deductions cannot underflow.`,
      starterCode: `export function applyDebit(balance, amount) {\n  return balance - amount;\n}`,
      verify: (code) => verifyLab('api_bounds', code),
    },
    {
      ...LAB_META.docker_hardening,
      evidenceNote: dockerEvidence,
      prompt: `Harden the ${archetype} clean-room Dockerfile: replace :latest with a pinned version tag, add a non-root USER, and configure HEALTHCHECK.`,
      starterCode: `FROM node:latest\nWORKDIR /app\nCOPY . .\nCMD ["node", "src/app.js"]`,
      verify: (code) => verifyLab('docker_hardening', code),
    },
  ];
}

// ---------------------------------------------------------------------------
// SHA-256 Hash-Chained Mastery Ledger
// ---------------------------------------------------------------------------

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function loadLedger() {
  try {
    const raw = getStore().getItem(LEDGER_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export async function appendLedger(entryData) {
  const chain = loadLedger();
  const prevHash = chain.length > 0 ? chain[chain.length - 1].hash : GENESIS_HASH;
  const payload = {
    index: chain.length,
    timestamp: entryData.timestamp || new Date().toISOString(),
    labId: entryData.labId,
    passed: Boolean(entryData.passed),
    masteryBefore: entryData.masteryBefore,
    masteryAfter: entryData.masteryAfter,
    specimen: entryData.specimen || '',
  };
  const hash = await sha256Hex(prevHash + canonicalJson(payload));
  const entry = {
    ...payload,
    prev_hash: prevHash,
    hash,
  };
  const nextChain = [...chain, entry];
  try {
    getStore().setItem(LEDGER_KEY, JSON.stringify(nextChain));
  } catch {}
  return { entry, chain: nextChain };
}

export async function verifyLedgerChain(entries = loadLedger()) {
  if (!Array.isArray(entries)) return false;
  for (let i = 0; i < entries.length; i++) {
    const item = entries[i];
    if (!item || typeof item !== 'object') return false;
    const expectedPrev = i === 0 ? GENESIS_HASH : entries[i - 1].hash;
    if (item.prev_hash !== expectedPrev) return false;
    const { prev_hash, hash, ...payload } = item;
    const expectedHash = await sha256Hex(prev_hash + canonicalJson(payload));
    if (hash !== expectedHash) return false;
  }
  return true;
}
