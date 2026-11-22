import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createStoreZip, forgeStarterZip } from '../src/zipforge.js';
import {
  MAX_FILE_BYTES,
  SecurityError,
  readRange,
  parseBinary,
  createFintechWalletApk,
  createSyntheticXapk,
  createFairplaySampleIpa,
  createArcadeEngineExe,
  createInstallerSampleMsi,
  createSyntheticPkg,
  createEdgeSensorKitZip,
} from '../src/parser.js';
import {
  scoreRisk,
  updateBKT,
  analyzeWithML,
  P_L0,
} from '../src/ml.js';
import {
  composeLabs,
  verifyLab,
  appendLedger,
  verifyLedgerChain,
} from '../src/labs.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');

test('1. All 7 synthetic formats parse accurately and readRange works on Blob and Uint8Array', async () => {
  assert.equal(MAX_FILE_BYTES, 512 * 1024 * 1024);

  const sampleU8 = new Uint8Array([10, 20, 30, 40, 50]);
  const sampleBlob = new Blob([sampleU8]);
  assert.deepEqual(Array.from(await readRange(sampleU8, 1, 4)), [20, 30, 40]);
  assert.deepEqual(Array.from(await readRange(sampleBlob, 2, 99)), [30, 40, 50]);

  const apk = await parseBinary(new Blob([createFintechWalletApk()]), 'fintech_wallet.apk');
  assert.equal(apk.format, 'apk');
  assert.equal(apk.dex.version, '037');
  assert.ok(apk.dex.stringIdsSize > 0);
  assert.ok(apk.dex.methodIdsSize > 0);
  assert.ok(apk.permissions.includes('android.permission.READ_CONTACTS'));
  assert.equal(apk.cleartextTraffic, true);

  const xapk = await parseBinary(createSyntheticXapk(), 'split_wallet.xapk');
  assert.equal(xapk.format, 'xapk');
  assert.equal(xapk.xapk.xapkVersion, 2);
  assert.ok(xapk.xapk.splitApks.includes('base.apk'));
  assert.ok(xapk.xapk.abis.includes('arm64-v8a'));
  assert.ok(xapk.xapk.obbPacks.some((o) => o.endsWith('.obb')));
  assert.equal(xapk.xapk.baseApkInspected, true);

  const ipa = await parseBinary(createFairplaySampleIpa(), 'fairplay_sample.ipa');
  assert.equal(ipa.format, 'ipa');
  assert.equal(ipa.macho.isFat, true);
  assert.equal(ipa.macho.cryptid, 1);
  assert.equal(ipa.macho.fairplayEncrypted, true);
  assert.ok(ipa.frameworks.includes('CryptoKit.framework'));

  const exe = await parseBinary(createArcadeEngineExe(), 'arcade_engine.exe');
  assert.equal(exe.format, 'exe');
  const textSec = exe.sections.find((s) => s.name === '.text');
  const upxSec = exe.sections.find((s) => s.name === '.upx0');
  assert.equal(textSec.entropy, 0);
  assert.ok(upxSec.entropy > 7.2);
  assert.equal(upxSec.entropy, 8);
  assert.equal(upxSec.packed, true);
  assert.ok(exe.pe.dlls.includes('d3d11.dll'));
  assert.ok(exe.pe.dlls.includes('WS2_32.dll'));

  const msi = await parseBinary(createInstallerSampleMsi(), 'installer_sample.msi');
  assert.equal(msi.format, 'msi');
  assert.equal(msi.ole2.validOle2, true);
  assert.equal(msi.ole2.hasCab, true);
  assert.ok(msi.ole2.markers.includes('ProductName'));

  const pkgBytes = await createSyntheticPkg();
  const pkg = await parseBinary(new Blob([pkgBytes]), 'installer_sample.pkg');
  assert.equal(pkg.format, 'pkg');
  assert.equal(pkg.pkg.signed, true);
  assert.ok(pkg.pkg.files.includes('Distribution'));
  assert.ok(pkg.pkg.files.includes('PackageInfo'));
  assert.ok(pkg.pkg.files.includes('Payload'));
  assert.ok(pkg.pkg.files.includes('Scripts'));

  const zip = await parseBinary(createEdgeSensorKitZip(), 'edge_sensor_kit.zip');
  assert.equal(zip.format, 'zip');
  assert.ok(zip.zip.manifests.includes('requirements.txt'));
  assert.ok(zip.zip.manifests.includes('Dockerfile'));
  assert.ok(zip.zip.schemas.includes('schemas/telemetry.sqlite'));
  assert.ok(zip.zip.mlModels.includes('models/anomaly_detector.onnx'));
});

test('2. Security guards reject zip-bomb (>1MB & ratio>100, or >16MB extract) and "../" traversal before inflate', async () => {
  const traversalZip = createStoreZip([{ name: '../escaped.txt', content: 'payload' }]);
  await assert.rejects(
    () => parseBinary(traversalZip, 'traversal.zip'),
    (err) => err instanceof SecurityError && err.message === 'PATH_TRAVERSAL'
  );

  // Guard A: entry > 1_048_576 with ratio > 100
  const bombZip = createStoreZip([{ name: 'payload.bin', content: new Uint8Array(100) }]);
  const bombView = new DataView(bombZip.buffer, bombZip.byteOffset, bombZip.byteLength);
  let cdPos = -1;
  for (let i = 0; i <= bombZip.length - 4; i++) {
    if (bombView.getUint32(i, true) === 0x02014b50) {
      cdPos = i;
      break;
    }
  }
  assert.notEqual(cdPos, -1);
  bombView.setUint32(cdPos + 24, 2_000_000, true); // ratio 20,000 > 100
  await assert.rejects(
    () => parseBinary(bombZip, 'bomb.zip'),
    (err) => err instanceof SecurityError && err.message === 'ZIP_BOMB'
  );

  // Guard B: metadata extraction > 16 MB
  const bigMetaZip = createStoreZip([{ name: 'AndroidManifest.xml', content: new Uint8Array(64) }]);
  const bigView = new DataView(bigMetaZip.buffer, bigMetaZip.byteOffset, bigMetaZip.byteLength);
  let bigCd = -1;
  for (let i = 0; i <= bigMetaZip.length - 4; i++) {
    if (bigView.getUint32(i, true) === 0x02014b50) {
      bigCd = i;
      break;
    }
  }
  assert.notEqual(bigCd, -1);
  // Set compressedSize=200_000 (ratio ~85 <= 100) and uncompressedSize=17 MB (> 16 MB)
  bigView.setUint32(bigCd + 20, 200_000, true);
  bigView.setUint32(bigCd + 24, 17 * 1024 * 1024, true);
  await assert.rejects(
    () => parseBinary(bigMetaZip, 'oversize_manifest.apk'),
    (err) => err instanceof SecurityError && err.message === 'ZIP_BOMB'
  );
});

test('3. ML archetype classification, risk attributions, and BKT mastery progression', async () => {
  const apk = await parseBinary(createFintechWalletApk(), 'fintech_wallet.apk');
  const exe = await parseBinary(createArcadeEngineExe(), 'arcade_engine.exe');
  const zip = await parseBinary(createEdgeSensorKitZip(), 'edge_sensor_kit.zip');

  const apkMl = analyzeWithML(apk);
  const exeMl = analyzeWithML(exe);
  const zipMl = analyzeWithML(zip);

  assert.equal(apkMl.topArchetype, 'Fintech / Payments');
  assert.equal(exeMl.topArchetype, '2D/3D Game');
  assert.equal(zipMl.topArchetype, 'IoT / Hardware');

  const probSum = Object.values(apkMl.probabilities).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(probSum - 1.0) < 1e-6);

  assert.ok(apkMl.risk.attributions.length > 0);
  assert.ok(exeMl.risk.score > 50);
  assert.ok(scoreRisk(exe.features).attributions.length > 0);

  const p1 = updateBKT(P_L0, true);
  const p2 = updateBKT(p1, true);
  assert.ok(p1 > P_L0);
  assert.ok(p2 > p1);
});

test('4. All 4 labs fail buggy snippets, pass fixed snippets, and verify hash-chained ledger', async () => {
  const apk = await parseBinary(createFintechWalletApk(), 'fintech_wallet.apk');
  const labs = composeLabs(apk, analyzeWithML(apk));
  assert.equal(labs.length, 4);

  assert.equal(verifyLab('sqlite_safety', 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")').passed, false);
  assert.equal(verifyLab('sqlite_safety', 'db.prepare("SELECT * FROM t WHERE id = " + uid).get()').passed, false);
  assert.equal(verifyLab('sqlite_safety', 'cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))').passed, true);
  assert.equal(verifyLab('sqlite_safety', 'db.prepare("SELECT * FROM t WHERE id = ?").get(uid)').passed, true);

  assert.equal(verifyLab('api_bounds', 'return balance - amount;').passed, false);
  assert.equal(verifyLab('api_bounds', 'return Math.max(0, balance - amount);').passed, true);
  assert.equal(verifyLab('api_bounds', 'return max(0, balance - amount)').passed, true);

  assert.equal(
    verifyLab('permission_hardening', '<application android:usesCleartextTraffic="true"><uses-permission android:name="android.permission.READ_CONTACTS"/></application>').passed,
    false
  );
  assert.equal(
    verifyLab('permission_hardening', '<application android:usesCleartextTraffic="false"><uses-permission android:name="android.permission.INTERNET"/></application>').passed,
    true
  );

  assert.equal(verifyLab('docker_hardening', 'FROM node:latest\nCMD ["node","app.js"]').passed, false);
  assert.equal(
    verifyLab('docker_hardening', 'FROM node:22.14.0-alpine\nUSER node\nHEALTHCHECK CMD node -e "process.exit(0)"\nCMD ["node","app.js"]').passed,
    true
  );

  await appendLedger({ labId: 'permission_hardening', passed: true, masteryBefore: 0.25, masteryAfter: 0.81, specimen: 'fintech_wallet.apk' });
  const { chain } = await appendLedger({ labId: 'sqlite_safety', passed: true, masteryBefore: 0.25, masteryAfter: 0.81, specimen: 'fintech_wallet.apk' });

  assert.equal(await verifyLedgerChain(chain), true);

  const tampered = structuredClone(chain);
  tampered[0].masteryAfter = 0.99;
  assert.equal(await verifyLedgerChain(tampered), false);
});

test('5. Forged starter zip round-trips through parseBinary with hardened artifacts', async () => {
  const apk = await parseBinary(createFintechWalletApk(), 'fintech_wallet.apk');
  const ml = analyzeWithML(apk);
  const forged = forgeStarterZip(apk, ml, {
    permission_hardening: 0.82,
    sqlite_safety: 0.61,
    api_bounds: 0.25,
    docker_hardening: 0.25,
  });

  const roundTrip = await parseBinary(forged, 'cleanroom_starter.zip');
  assert.equal(roundTrip.format, 'zip');
  const names = roundTrip.zip.entries;
  for (const expected of [
    'MOOC_SYLLABUS.md',
    'ARCHITECTURE.md',
    'THREAT_MODEL.md',
    'Dockerfile',
    'render.yaml',
    '.github/workflows/ci.yml',
  ]) {
    assert.ok(names.includes(expected), `Missing ${expected} in forged zip`);
  }

  const dockerfile = roundTrip.zip.manifestContents['Dockerfile'] || '';
  assert.match(dockerfile, /^USER\s+(?!root\b|0\b)\S+/m);
  assert.doesNotMatch(dockerfile, /:latest/i);
  assert.match(dockerfile, /^HEALTHCHECK\s+/m);
});

test('6. index.html contains Matcha & Linen tokens, landing/studio views, intro details, and zero external URLs', async () => {
  const html = await fs.readFile(path.join(ROOT_DIR, 'index.html'), 'utf8');
  for (const token of [
    '#f5f2eb',
    '#58725b',
    '#c88a36',
    '#b85c38',
    'DECONSTRUCTED',
    'John Dominic Ragudo',
    'id="landing-view"',
    'id="studio-view"',
    'Open X-Ray Studio',
    '.apk,.xapk,.ipa,.exe,.msi,.pkg,.zip',
  ]) {
    assert.ok(html.includes(token), `index.html missing ${token}`);
  }
  assert.doesNotMatch(html, /<(?:script|link)\b[^>]*\b(?:src|href)\s*=\s*["']https?:\/\//i);
});
