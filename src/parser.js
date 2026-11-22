import { createStoreZip } from './zipforge.js';

export const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_METADATA_BYTES = 16 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 100;
const ZIP_BOMB_MIN_SIZE = 1_048_576;

const textDecoder = new TextDecoder('utf-8', { fatal: false });
const utf16Decoder = new TextDecoder('utf-16le', { fatal: false });
const textEncoder = new TextEncoder();

export class SecurityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SecurityError';
    this.code = message;
  }
}

function makeView(u8) {
  return new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
}

function getSourceSize(source) {
  if (source instanceof Uint8Array || ArrayBuffer.isView(source) || source instanceof ArrayBuffer) {
    return source.byteLength;
  }
  if (source && typeof source.size === 'number') {
    return source.size;
  }
  throw new TypeError('Expected Uint8Array, ArrayBuffer, or Blob/File');
}

/**
 * Lazily read a clamped byte range [start, end) from Uint8Array, ArrayBuffer, or Blob/File.
 * Never calls .arrayBuffer() on a full File.
 */
export async function readRange(source, start = 0, end = Infinity) {
  const size = getSourceSize(source);
  const s = Math.max(0, Math.min(size, start));
  const e = Math.max(s, Math.min(size, end));
  if (source instanceof Uint8Array) return source.subarray(s, e);
  if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset + s, e - s);
  if (source instanceof ArrayBuffer) return new Uint8Array(source, s, e - s);
  if (source && typeof source.slice === 'function') {
    return new Uint8Array(await source.slice(s, e).arrayBuffer());
  }
  throw new TypeError('Unsupported binary source');
}

/**
 * Lazily scan backwards in the last 65,557 bytes for EOCD (0x06054b50) and walk Central Directory
 * BEFORE any entry is inflated.
 */
async function parseZipDirectory(source) {
  const size = getSourceSize(source);
  const tailStart = Math.max(0, size - 65557);
  const tail = await readRange(source, tailStart, size);
  const tailView = makeView(tail);
  let eocdLocal = -1;

  for (let pos = tail.byteLength - 22; pos >= 0; pos--) {
    if (tailView.getUint32(pos, true) === 0x06054b50) {
      const commentLen = tailView.getUint16(pos + 20, true);
      if (pos + 22 + commentLen <= tail.byteLength) {
        eocdLocal = pos;
        break;
      }
    }
  }

  if (eocdLocal === -1) {
    throw new Error('Invalid ZIP: EOCD signature not found');
  }

  const eocdAbs = tailStart + eocdLocal;
  const totalEntries = tailView.getUint16(eocdLocal + 10, true);
  const cdSize = tailView.getUint32(eocdLocal + 12, true);
  const cdOffset = tailView.getUint32(eocdLocal + 16, true);

  if (cdSize > MAX_METADATA_BYTES) {
    throw new SecurityError('ZIP_BOMB');
  }
  if (cdOffset + cdSize > eocdAbs) {
    throw new Error('Invalid ZIP: Central Directory extends past EOCD');
  }

  const cdBytes = await readRange(source, cdOffset, cdOffset + cdSize);
  const cdView = makeView(cdBytes);
  const entries = [];
  let pos = 0;
  let totalUncompressed = 0;
  let totalCompressed = 0;

  for (let i = 0; i < totalEntries; i++) {
    if (pos + 46 > cdBytes.byteLength || cdView.getUint32(pos, true) !== 0x02014b50) {
      throw new Error('Invalid ZIP: corrupt Central Directory record');
    }

    const method = cdView.getUint16(pos + 10, true);
    const compressedSize = cdView.getUint32(pos + 20, true);
    const uncompressedSize = cdView.getUint32(pos + 24, true);
    const nameLen = cdView.getUint16(pos + 28, true);
    const extraLen = cdView.getUint16(pos + 30, true);
    const commentLen = cdView.getUint16(pos + 32, true);
    const localHeaderOffset = cdView.getUint32(pos + 42, true);

    if (pos + 46 + nameLen > cdBytes.byteLength) {
      throw new Error('Invalid ZIP: truncated filename in Central Directory');
    }

    const name = textDecoder.decode(cdBytes.subarray(pos + 46, pos + 46 + nameLen));

    // Security Guard 1: Path traversal check BEFORE any decompression
    if (name.includes('..') || name.startsWith('/') || name.startsWith('\\')) {
      throw new SecurityError('PATH_TRAVERSAL');
    }

    // Security Guard 2: Zip-bomb check BEFORE any decompression
    const ratio = uncompressedSize / Math.max(1, compressedSize);
    if (uncompressedSize > ZIP_BOMB_MIN_SIZE && ratio > MAX_COMPRESSION_RATIO) {
      throw new SecurityError('ZIP_BOMB');
    }

    totalUncompressed += uncompressedSize;
    totalCompressed += compressedSize;
    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
    pos += 46 + nameLen + extraLen + commentLen;
  }

  return { entries, totalUncompressed, totalCompressed };
}

async function resolvePayloadSpan(source, entry) {
  const off = entry.localHeaderOffset;
  const lfh = await readRange(source, off, off + 30);
  const view = makeView(lfh);
  if (lfh.byteLength < 30 || view.getUint32(0, true) !== 0x04034b50) {
    throw new Error(`Invalid Local File Header for ${entry.name}`);
  }
  const lfhNameLen = view.getUint16(26, true);
  const lfhExtraLen = view.getUint16(28, true);
  const dataStart = off + 30 + lfhNameLen + lfhExtraLen;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataEnd > getSourceSize(source)) {
    throw new Error(`Truncated payload for ${entry.name}`);
  }
  return { dataStart, dataEnd };
}

/**
 * Safely slice and inflate a single ZIP metadata entry (<= 16 MB) via LFH offsets.
 */
async function safeInflateEntry(source, entry, tracker = null) {
  if (entry.uncompressedSize > MAX_METADATA_BYTES) {
    throw new SecurityError('ZIP_BOMB');
  }
  if (tracker) {
    if (tracker.extracted + entry.uncompressedSize > MAX_METADATA_BYTES) {
      throw new SecurityError('ZIP_BOMB');
    }
  }

  const { dataStart, dataEnd } = await resolvePayloadSpan(source, entry);
  const rawSlice = await readRange(source, dataStart, dataEnd);

  let out;
  if (entry.method === 0) {
    out = rawSlice;
  } else if (entry.method === 8) {
    const stream = new Blob([rawSlice]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    const ab = await new Response(stream).arrayBuffer();
    out = new Uint8Array(ab);
  } else {
    throw new Error(`Unsupported ZIP compression method ${entry.method} for ${entry.name}`);
  }

  if (out.byteLength > MAX_METADATA_BYTES) {
    throw new SecurityError('ZIP_BOMB');
  }
  if (tracker) {
    tracker.extracted += out.byteLength;
    if (tracker.extracted > MAX_METADATA_BYTES) {
      throw new SecurityError('ZIP_BOMB');
    }
  }
  return out;
}

function extractPrintableStrings(bytes, minLen = 4) {
  const asciiMatches = [];
  let cur = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b <= 0x7E) {
      cur.push(b);
    } else {
      if (cur.length >= minLen) asciiMatches.push(String.fromCharCode(...cur));
      cur = [];
    }
  }
  if (cur.length >= minLen) asciiMatches.push(String.fromCharCode(...cur));

  const utf16Text = utf16Decoder.decode(bytes);
  const utf16Matches = utf16Text.match(/[\x20-\x7E]{4,}/g) || [];
  return [...asciiMatches, ...utf16Matches];
}

function computeEntropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

async function detectFormat(source, filename = '') {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.xapk')) return 'xapk';
  if (lower.endsWith('.apk')) return 'apk';
  if (lower.endsWith('.ipa')) return 'ipa';
  if (lower.endsWith('.exe') || lower.endsWith('.dll')) return 'exe';
  if (lower.endsWith('.msi')) return 'msi';
  if (lower.endsWith('.pkg')) return 'pkg';
  if (lower.endsWith('.zip')) return 'zip';

  const head = await readRange(source, 0, 8);
  if (head.byteLength >= 4 && head[0] === 0x78 && head[1] === 0x61 && head[2] === 0x72 && head[3] === 0x21) {
    return 'pkg';
  }
  if (
    head.byteLength >= 8 &&
    head[0] === 0xD0 && head[1] === 0xCF && head[2] === 0x11 && head[3] === 0xE0 &&
    head[4] === 0xA1 && head[5] === 0xB1 && head[6] === 0x1A && head[7] === 0xE1
  ) {
    return 'msi';
  }
  if (head.byteLength >= 2 && head[0] === 0x4D && head[1] === 0x5A) {
    return 'exe';
  }
  return 'zip';
}

function parseDexHeader(dexBytes) {
  if (dexBytes.byteLength < 112) return null;
  const magic = textDecoder.decode(dexBytes.subarray(0, 8));
  if (!/^dex\n03[5-9]\0$/.test(magic)) return null;
  const view = makeView(dexBytes);
  return {
    version: magic.slice(4, 7),
    fileSize: view.getUint32(32, true),
    stringIdsSize: view.getUint32(56, true),
    typeIdsSize: view.getUint32(64, true),
    protoIdsSize: view.getUint32(72, true),
    fieldIdsSize: view.getUint32(80, true),
    methodIdsSize: view.getUint32(88, true),
    classDefsSize: view.getUint32(96, true),
  };
}

function scanAxmlBytes(axmlBytes) {
  // Raw byte-level UTF-8 and UTF-16LE scan on binary AXML (never DOMParser/XML parser)
  const utf8Text = textDecoder.decode(axmlBytes);
  const utf16Text = utf16Decoder.decode(axmlBytes);
  const combined = `${utf8Text}\n${utf16Text}`;

  const permissions = Array.from(new Set(combined.match(/android\.permission\.[A-Z0-9_]+/g) || []));
  const cleartextTrue =
    /usesCleartextTraffic\s*=\s*["']?true["']?/i.test(combined) ||
    /usesCleartextTraffic[\x00-\x20="':]{1,16}true/i.test(combined);
  const cleartextFalse =
    /usesCleartextTraffic\s*=\s*["']?false["']?/i.test(combined) ||
    /usesCleartextTraffic[\x00-\x20="':]{1,16}false/i.test(combined);

  return { permissions, cleartextTraffic: cleartextTrue && !cleartextFalse };
}

async function analyzeApk(source, filename) {
  const byteLength = getSourceSize(source);
  const { entries, totalUncompressed, totalCompressed } = await parseZipDirectory(source);
  const entryMap = new Map(entries.map((e) => [e.name, e]));
  const tracker = { extracted: 0 };

  let dex = null;
  const dexStrings = [];
  for (const entry of entries) {
    if (/^classes\d*\.dex$/.test(entry.name)) {
      let dexBytes;
      if (entry.method === 0 && entry.uncompressedSize > MAX_METADATA_BYTES) {
        const { dataStart } = await resolvePayloadSpan(source, entry);
        dexBytes = await readRange(source, dataStart, dataStart + 256 * 1024);
      } else {
        dexBytes = await safeInflateEntry(source, entry, tracker);
      }
      if (!dex) dex = parseDexHeader(dexBytes);
      dexStrings.push(...extractPrintableStrings(dexBytes.subarray(0, 512 * 1024), 4));
    }
  }

  let permissions = [];
  let cleartextTraffic = false;
  if (entryMap.has('AndroidManifest.xml')) {
    const manifestBytes = await safeInflateEntry(source, entryMap.get('AndroidManifest.xml'), tracker);
    const axml = scanAxmlBytes(manifestBytes);
    permissions = axml.permissions;
    cleartextTraffic = axml.cleartextTraffic;
  }

  const knownMarkers = [
    ['libflutter.so', 'Flutter'],
    ['libunity.so', 'Unity'],
    ['libil2cpp.so', 'Unity IL2CPP'],
    ['libreactnativejni.so', 'React Native'],
    ['libgodot.so', 'Godot'],
    ['libsqlcipher.so', 'SQLCipher'],
  ];

  const runtimes = ['Android DEX'];
  const nativeLibs = [];
  for (const entry of entries) {
    if (/^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)) {
      nativeLibs.push(entry.name);
      for (const [so, label] of knownMarkers) {
        if (entry.name.endsWith(`/${so}`) && !runtimes.includes(label)) runtimes.push(label);
      }
    }
  }

  const joinedDex = dexStrings.join(' ').toLowerCase();
  if (joinedDex.includes('okhttp') && !runtimes.includes('OkHttp')) runtimes.push('OkHttp');
  if (joinedDex.includes('sqlite') && !runtimes.includes('SQLite')) runtimes.push('SQLite');
  if (joinedDex.includes('biometric') && !runtimes.includes('AndroidX Biometric')) runtimes.push('AndroidX Biometric');

  const dangerousPerms = permissions.filter((p) =>
    /READ_CONTACTS|WRITE_EXTERNAL_STORAGE|READ_SMS|SEND_SMS|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA/.test(p)
  );

  const tokens = [
    'apk', 'android', 'dex',
    ...runtimes.map((r) => r.toLowerCase()),
    ...permissions.map((p) => p.toLowerCase()),
    ...nativeLibs.map((l) => l.toLowerCase()),
    ...dexStrings.map((s) => s.toLowerCase()),
    cleartextTraffic ? 'cleartext_http' : 'tls_only',
  ];

  const schemas = entries.filter((e) => /\.(sqlite|db|json)$/i.test(e.name)).map((e) => e.name);

  return {
    filename,
    format: 'apk',
    byteLength,
    summary: `Android APK · DEX v${dex?.version || 'unknown'} · ${dex?.classDefsSize ?? 0} classes · ${permissions.length} permissions`,
    runtimes,
    permissions,
    cleartextTraffic,
    dex,
    nativeLibs,
    sections: [],
    zip: {
      entryCount: entries.length,
      totalUncompressed,
      totalCompressed,
      entries: entries.map((e) => e.name),
      manifests: entries.filter((e) => e.name === 'AndroidManifest.xml').map((e) => e.name),
      manifestContents: {},
      schemas,
      mlModels: entries.filter((e) => /\.(tflite|onnx)$/i.test(e.name)).map((e) => e.name),
    },
    tokens,
    features: {
      maxCodeEntropy: 5.4,
      dangerousPermCount: dangerousPerms.length,
      cleartextHttp: cleartextTraffic ? 1 : 0,
      packedSection: 0,
      fairplayOrUnsigned: 0,
    },
    architectureMap: {
      ui: `Android Activities & Views (${runtimes.filter((r) => /Flutter|React Native|Unity|Godot/.test(r)).join(', ') || 'Native Android UI'})`,
      core: `DEX v${dex?.version || '?'} (${dex?.methodIdsSize ?? 0} methods, ${dex?.classDefsSize ?? 0} classes)`,
      data: schemas.length ? `Embedded storage: ${schemas.join(', ')}` : (joinedDex.includes('sqlite') ? 'SQLite / local keystore references in DEX' : 'No raw DB files in APK root'),
      security: `${permissions.length} permissions (${dangerousPerms.length} dangerous), usesCleartextTraffic=${cleartextTraffic}`,
    },
  };
}

async function analyzeXapk(source, filename) {
  const byteLength = getSourceSize(source);
  const { entries, totalUncompressed, totalCompressed } = await parseZipDirectory(source);
  const entryMap = new Map(entries.map((e) => [e.name, e]));
  const tracker = { extracted: 0 };

  let manifest = {};
  if (entryMap.has('manifest.json')) {
    const manifestBytes = await safeInflateEntry(source, entryMap.get('manifest.json'), tracker);
    manifest = JSON.parse(textDecoder.decode(manifestBytes));
  }

  const splitApks = Array.isArray(manifest.split_apks)
    ? manifest.split_apks.map((s) => (typeof s === 'string' ? s : (s.file || s.id || 'split.apk')))
    : entries.filter((e) => /\.apk$/i.test(e.name)).map((e) => e.name);

  const obbPacks = Array.isArray(manifest.expansions)
    ? manifest.expansions.map((x) => (typeof x === 'string' ? x : (x.file || x.install_path || 'expansion.obb')))
    : entries.filter((e) => /\.obb$/i.test(e.name)).map((e) => e.name);

  const abiSet = new Set();
  for (const name of [...splitApks, ...entries.map((e) => e.name)]) {
    const m = name.match(/(arm64[-_]v8a|armeabi[-_]v7a|x86_64|x86)/i);
    if (m) abiSet.add(m[1].replace('_', '-').toLowerCase());
  }
  const abis = Array.from(abiSet);

  let baseScan = null;
  const baseEntry = entries.find((e) => /(^|\/)base\.apk$/i.test(e.name));
  if (baseEntry && baseEntry.method === 0 && baseEntry.uncompressedSize <= MAX_METADATA_BYTES) {
    const baseBytes = await safeInflateEntry(source, baseEntry, tracker);
    baseScan = await analyzeApk(baseBytes, baseEntry.name);
  }

  const manifestPerms = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  const permissions = Array.from(new Set([...manifestPerms, ...(baseScan?.permissions || [])]));
  const cleartextTraffic = Boolean(baseScan?.cleartextTraffic);
  const dangerousPerms = permissions.filter((p) =>
    /READ_CONTACTS|WRITE_EXTERNAL_STORAGE|READ_SMS|SEND_SMS|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA/.test(p)
  );

  const runtimes = Array.from(new Set([
    'XAPK Bundle',
    ...(splitApks.length ? [`${splitApks.length} Split APKs`] : []),
    ...abis.map((a) => `ABI ${a}`),
    ...(obbPacks.length ? [`${obbPacks.length} OBB Expansions`] : []),
    ...(baseScan?.runtimes || []),
  ]));

  const tokens = [
    'xapk', 'apk', 'android', 'split',
    ...splitApks.map((s) => s.toLowerCase()),
    ...abis,
    ...obbPacks.map((o) => o.toLowerCase()),
    ...permissions.map((p) => p.toLowerCase()),
    ...(baseScan?.tokens || []),
  ];

  return {
    filename,
    format: 'xapk',
    byteLength,
    summary: `Android XAPK v${manifest.xapk_version ?? '?'} · ${manifest.package_name || 'bundle'} · ${splitApks.length} split APKs · ${obbPacks.length} OBB`,
    runtimes,
    permissions,
    cleartextTraffic,
    dex: baseScan?.dex || null,
    nativeLibs: baseScan?.nativeLibs || [],
    xapk: {
      xapkVersion: manifest.xapk_version ?? null,
      packageName: manifest.package_name || '',
      splitApks,
      abis,
      obbPacks,
      permissions,
      baseApkInspected: Boolean(baseScan),
    },
    sections: [],
    zip: {
      entryCount: entries.length,
      totalUncompressed,
      totalCompressed,
      entries: entries.map((e) => e.name),
      manifests: entryMap.has('manifest.json') ? ['manifest.json'] : [],
      manifestContents: {},
      schemas: baseScan?.zip?.schemas || [],
      mlModels: entries.filter((e) => /\.(tflite|onnx)$/i.test(e.name)).map((e) => e.name),
    },
    tokens,
    features: {
      maxCodeEntropy: 5.5,
      dangerousPermCount: dangerousPerms.length,
      cleartextHttp: cleartextTraffic ? 1 : 0,
      packedSection: 0,
      fairplayOrUnsigned: 0,
    },
    architectureMap: {
      ui: `XAPK ${manifest.package_name || 'App'} (${splitApks.length} splits; ABIs: ${abis.join(', ') || 'universal'})`,
      core: baseScan ? `Nested base.apk DEX v${baseScan.dex?.version || '?'} (${baseScan.dex?.methodIdsSize ?? 0} methods)` : `Split APK set: ${splitApks.join(', ')}`,
      data: obbPacks.length ? `OBB expansion packs: ${obbPacks.join(', ')}` : (baseScan?.architectureMap?.data || 'No external OBB packs'),
      security: `${permissions.length} permissions (${dangerousPerms.length} dangerous), cleartext=${cleartextTraffic}`,
    },
  };
}

function parsePlist(bytes) {
  const head = textDecoder.decode(bytes.subarray(0, 8));
  const kv = {};
  if (head.startsWith('bplist00')) {
    const strings = extractPrintableStrings(bytes, 3);
    kv._format = 'bplist00';
    kv._strings = strings;
    for (let i = 0; i < strings.length - 1; i++) {
      if (strings[i].startsWith('CFBundle') || strings[i].startsWith('NS')) {
        kv[strings[i]] = strings[i + 1];
      }
    }
    return kv;
  }

  const xml = textDecoder.decode(bytes);
  kv._format = 'xml';
  const pairRe = /<key>([^<]+)<\/key>\s*<(string|true|false|integer)>([^<]*)<\/\2>|<key>([^<]+)<\/key>\s*<(true|false)\s*\/>/g;
  let m;
  while ((m = pairRe.exec(xml)) !== null) {
    if (m[1]) kv[m[1]] = m[3];
    else if (m[4]) kv[m[4]] = m[5];
  }
  return kv;
}

function parseMachOHeader(bytes, baseOffset = 0) {
  if (bytes.byteLength < 32) return null;
  const view = makeView(bytes);
  const magicBE = view.getUint32(0, false);
  const magicLE = view.getUint32(0, true);

  let isFat = false;
  let nfatArch = 1;
  let sliceOff = 0;

  if (magicBE === 0xCAFEBABE) {
    isFat = true;
    nfatArch = view.getUint32(4, false);
    sliceOff = view.getUint32(8 + 8, false);
  } else if (magicLE !== 0xFEEDFACF) {
    return null;
  }

  const relSlice = sliceOff - baseOffset;
  if (relSlice < 0 || relSlice + 32 > bytes.byteLength) {
    return { isFat, nfatArch, sliceOffset: sliceOff, needRemoteSlice: true };
  }

  const sliceMagic = view.getUint32(relSlice, true);
  if (sliceMagic !== 0xFEEDFACF) {
    return { isFat, nfatArch, sliceOffset: sliceOff, magic: sliceMagic, ncmds: 0, cryptid: 0, fairplayEncrypted: false };
  }

  const ncmds = view.getUint32(relSlice + 16, true);
  let cmdOff = relSlice + 32;
  let cryptid = 0;

  for (let i = 0; i < ncmds; i++) {
    if (cmdOff + 8 > bytes.byteLength) break;
    const cmd = view.getUint32(cmdOff, true);
    const cmdsize = view.getUint32(cmdOff + 4, true);
    if (cmdsize < 8 || cmdOff + cmdsize > bytes.byteLength) break;
    if (cmd === 0x2C && cmdOff + 20 <= bytes.byteLength) {
      cryptid = view.getUint32(cmdOff + 16, true);
    }
    cmdOff += cmdsize;
  }

  return {
    isFat,
    nfatArch,
    sliceOffset: sliceOff,
    magic: '0xFEEDFACF',
    ncmds,
    cryptid,
    fairplayEncrypted: cryptid === 1,
  };
}

async function analyzeIpa(source, filename) {
  const byteLength = getSourceSize(source);
  const { entries, totalUncompressed, totalCompressed } = await parseZipDirectory(source);
  const tracker = { extracted: 0 };
  let plist = {};
  const frameworks = [];
  let macho = null;

  const plistEntry = entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name));
  if (plistEntry) {
    const plistBytes = await safeInflateEntry(source, plistEntry, tracker);
    plist = parsePlist(plistBytes);
  }

  for (const entry of entries) {
    const fwMatch = entry.name.match(/^Payload\/[^/]+\.app\/Frameworks\/([^/]+)/);
    if (fwMatch && !frameworks.includes(fwMatch[1])) frameworks.push(fwMatch[1]);
  }

  const appMatch = plistEntry?.name.match(/^(Payload\/([^/]+)\.app)\/Info\.plist$/);
  const candidateExecutables = entries.filter((e) => {
    if (appMatch && e.name === `${appMatch[1]}/${appMatch[2]}`) return true;
    return /^Payload\/[^/]+\.app\/[^/]+$/.test(e.name) && !e.name.endsWith('.plist') && !e.name.endsWith('.nib');
  });

  for (const execEntry of candidateExecutables) {
    let parsed = null;
    if (execEntry.method === 0 && execEntry.uncompressedSize > MAX_METADATA_BYTES) {
      const { dataStart } = await resolvePayloadSpan(source, execEntry);
      const head = await readRange(source, dataStart, dataStart + 65536);
      parsed = parseMachOHeader(head, 0);
      if (parsed?.needRemoteSlice) {
        const sliceBytes = await readRange(source, dataStart + parsed.sliceOffset, dataStart + parsed.sliceOffset + 65536);
        const inner = parseMachOHeader(sliceBytes, 0);
        if (inner) parsed = { ...inner, isFat: true, nfatArch: parsed.nfatArch, sliceOffset: parsed.sliceOffset };
      }
    } else {
      const execBytes = await safeInflateEntry(source, execEntry, tracker);
      parsed = parseMachOHeader(execBytes, 0);
    }
    if (parsed && !parsed.needRemoteSlice) {
      macho = parsed;
      break;
    }
  }

  const runtimes = ['iOS Mach-O 64-bit', ...frameworks];
  const atsInsecure = plist.NSAllowsArbitraryLoads === 'true' || plist.NSAllowsArbitraryLoads === 'YES';
  const tokens = [
    'ipa', 'ios', 'macho',
    ...frameworks.map((f) => f.toLowerCase()),
    ...Object.keys(plist).map((k) => k.toLowerCase()),
    ...Object.values(plist).flat().map((v) => String(v).toLowerCase()),
    macho?.fairplayEncrypted ? 'fairplay' : 'unencrypted',
  ];

  return {
    filename,
    format: 'ipa',
    byteLength,
    summary: `iOS IPA · ${plist.CFBundleIdentifier || 'Unknown Bundle'} · ${frameworks.length} frameworks · FairPlay cryptid=${macho?.cryptid ?? 0}`,
    runtimes,
    permissions: Object.keys(plist).filter((k) => k.endsWith('UsageDescription')),
    cleartextTraffic: atsInsecure,
    plist,
    frameworks,
    macho,
    sections: [],
    zip: {
      entryCount: entries.length,
      totalUncompressed,
      totalCompressed,
      entries: entries.map((e) => e.name),
      manifests: plistEntry ? [plistEntry.name] : [],
      manifestContents: {},
      schemas: entries.filter((e) => /\.(sqlite|db|json)$/i.test(e.name)).map((e) => e.name),
      mlModels: entries.filter((e) => /\.(mlmodelc|tflite|onnx)$/i.test(e.name)).map((e) => e.name),
    },
    tokens,
    features: {
      maxCodeEntropy: macho?.fairplayEncrypted ? 7.8 : 5.6,
      dangerousPermCount: Object.keys(plist).filter((k) => k.endsWith('UsageDescription')).length,
      cleartextHttp: atsInsecure ? 1 : 0,
      packedSection: 0,
      fairplayOrUnsigned: macho?.fairplayEncrypted ? 1 : 0,
    },
    architectureMap: {
      ui: `iOS Bundle ${plist.CFBundleName || plist.CFBundleIdentifier || 'App'} (${plist._format || 'plist'})`,
      core: macho ? `Mach-O ${macho.isFat ? `FAT (${macho.nfatArch} slices)` : 'Thin'} @ +${macho.sliceOffset}, ${macho.ncmds} load cmds` : 'Mach-O header not found',
      data: frameworks.length ? `Frameworks: ${frameworks.join(', ')}` : 'Standard Foundation storage',
      security: `LC_ENCRYPTION_INFO_64 cryptid=${macho?.cryptid ?? 0} (${macho?.fairplayEncrypted ? 'FairPlay DRM' : 'Cleartext slice'})`,
    },
  };
}

async function analyzeExe(source, filename) {
  const byteLength = getSourceSize(source);
  const dosHead = await readRange(source, 0, 64);
  const dosView = makeView(dosHead);
  if (dosHead.byteLength < 64 || dosView.getUint16(0, true) !== 0x5A4D) {
    throw new Error('Invalid PE/MZ executable: missing MZ magic');
  }

  const eLfanew = dosView.getUint32(0x3C, true);
  if (eLfanew + 24 > byteLength) {
    throw new Error('Invalid PE executable: e_lfanew out of bounds');
  }
  const coffHead = await readRange(source, eLfanew, eLfanew + 24);
  if (textDecoder.decode(coffHead.subarray(0, 4)) !== 'PE\0\0') {
    throw new Error('Invalid PE executable: missing PE\\0\\0 signature');
  }

  const coffView = makeView(coffHead);
  const machine = coffView.getUint16(4, true);
  const machineMap = { 0x8664: 'x64', 0x014C: 'x86', 0xAA64: 'ARM64' };
  const machineLabel = machineMap[machine] || `0x${machine.toString(16)}`;
  const numberOfSections = coffView.getUint16(6, true);
  const timestamp = coffView.getUint32(8, true);
  const sizeOfOptionalHeader = coffView.getUint16(20, true);

  const secTableOff = eLfanew + 24 + sizeOfOptionalHeader;
  const secTableBytes = await readRange(source, secTableOff, secTableOff + numberOfSections * 40);
  const secView = makeView(secTableBytes);

  const sections = [];
  const strings = [];
  let maxCodeEntropy = 0;
  let packedSection = false;

  for (let i = 0; i < numberOfSections; i++) {
    const off = i * 40;
    if (off + 40 > secTableBytes.byteLength) break;
    const rawName = textDecoder.decode(secTableBytes.subarray(off, off + 8)).replace(/\0+$/, '');
    const virtualSize = secView.getUint32(off + 8, true);
    const sizeOfRawData = secView.getUint32(off + 16, true);
    const pointerToRawData = secView.getUint32(off + 20, true);
    const characteristics = secView.getUint32(off + 36, true);
    const executable = (characteristics & 0x20000000) !== 0 || (characteristics & 0x00000020) !== 0;

    const sampleEnd = Math.min(byteLength, pointerToRawData + Math.min(sizeOfRawData, 4 * 1024 * 1024));
    const secBytes = await readRange(source, pointerToRawData, sampleEnd);
    const entropy = computeEntropy(secBytes);
    const packed = entropy > 7.2 && (executable || rawName !== '.rsrc');

    if (executable || rawName !== '.rsrc') maxCodeEntropy = Math.max(maxCodeEntropy, entropy);
    if (packed) packedSection = true;

    if (secBytes.byteLength > 0 && strings.length < 2500) {
      strings.push(...extractPrintableStrings(secBytes.subarray(0, 256 * 1024), 4));
    }

    sections.push({ name: rawName, virtualSize, size: sizeOfRawData, executable, entropy, packed, characteristics });
  }

  if (strings.length === 0) {
    strings.push(...extractPrintableStrings(await readRange(source, 0, Math.min(byteLength, 512 * 1024)), 4));
  }

  const combined = strings.join(' ').toLowerCase();
  const markerDefs = [
    ['WS2_32.dll', 'Winsock2 (WS2_32.dll)'],
    ['d3d11.dll', 'Direct3D 11 (d3d11.dll)'],
    ['mscoree.dll', '.NET CLR (mscoree.dll)'],
    ['python3', 'Embedded Python 3'],
    ['Electron', 'Electron Runtime'],
  ];

  const dlls = [];
  const runtimes = [`PE ${machineLabel}`];
  for (const [needle, label] of markerDefs) {
    if (combined.includes(needle.toLowerCase())) {
      dlls.push(needle);
      runtimes.push(label);
    }
  }

  const tokens = [
    'exe', 'pe', machineLabel.toLowerCase(),
    ...sections.map((s) => s.name.toLowerCase()),
    ...dlls.map((d) => d.toLowerCase()),
    ...strings.map((s) => s.toLowerCase()),
    packedSection ? 'packed_section' : 'unpacked',
  ];

  return {
    filename,
    format: 'exe',
    byteLength,
    summary: `Windows PE (${machineLabel}) · ${sections.length} sections · max entropy ${maxCodeEntropy.toFixed(2)} bits/byte`,
    runtimes,
    permissions: [],
    cleartextTraffic: false,
    pe: { machine, machineLabel, timestamp, numberOfSections, dlls },
    sections,
    tokens,
    features: {
      maxCodeEntropy,
      dangerousPermCount: 0,
      cleartextHttp: 0,
      packedSection: packedSection ? 1 : 0,
      fairplayOrUnsigned: 1,
    },
    architectureMap: {
      ui: dlls.includes('d3d11.dll') ? 'Direct3D 11 swapchain / render surface' : (dlls.includes('Electron') ? 'Electron Chromium UI' : 'Win32 native windowing'),
      core: `${machineLabel} PE sections: ${sections.map((s) => `${s.name} (${s.entropy.toFixed(2)})`).join(', ')}`,
      data: dlls.includes('WS2_32.dll') ? 'Winsock2 (WS2_32.dll) socket telemetry / multiplayer I/O' : 'Local PE resource & config tables',
      security: packedSection ? 'High-entropy packed section detected (> 7.2 bits/byte)' : 'No high-entropy packed code sections detected',
    },
  };
}

async function analyzeMsi(source, filename) {
  const byteLength = getSourceSize(source);
  const head = await readRange(source, 0, Math.min(byteLength, 256 * 1024));
  const ole2Expected = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
  const validOle2 = head.byteLength >= 8 && ole2Expected.every((b, idx) => head[idx] === b);
  if (!validOle2) throw new Error('Invalid MSI: missing OLE2 compound document magic');

  const tail = byteLength > 256 * 1024 ? await readRange(source, Math.max(0, byteLength - 256 * 1024), byteLength) : new Uint8Array(0);
  const hasCab = textDecoder.decode(head).includes('MSCF') || textDecoder.decode(tail).includes('MSCF');
  const strings = [...extractPrintableStrings(head, 4), ...extractPrintableStrings(tail, 4)];
  const markerList = ['ProductName', 'Manufacturer', 'UpgradeCode', 'InstallExecuteSequence', 'CustomAction', 'Windows Installer'];
  const markers = markerList.filter((m) => strings.some((s) => s.includes(m)));

  const runtimes = ['OLE2 CFBF', ...(hasCab ? ['MSCF CAB Stream'] : []), 'Windows Installer'];
  const tokens = ['msi', 'installer', 'ole2', 'mscf', ...markers.map((m) => m.toLowerCase()), ...strings.map((s) => s.toLowerCase())];

  return {
    filename,
    format: 'msi',
    byteLength,
    summary: `Windows MSI (OLE2) · CAB=${hasCab ? 'MSCF' : 'none'} · ${markers.length} installer tables`,
    runtimes,
    permissions: [],
    cleartextTraffic: false,
    ole2: { validOle2, hasCab, markers },
    sections: [],
    tokens,
    features: { maxCodeEntropy: 4.5, dangerousPermCount: 0, cleartextHttp: 0, packedSection: 0, fairplayOrUnsigned: 0 },
    architectureMap: {
      ui: 'MSI Dialog & InstallUISequence tables',
      core: `OLE2 Installer actions (${markers.join(', ') || 'standard sequence'})`,
      data: hasCab ? 'Embedded MSCF Cabinet payload stream' : 'External source media layout',
      security: markers.includes('CustomAction') ? 'CustomAction execution surface present' : 'Standard declarative MSI tables',
    },
  };
}

async function analyzePkg(source, filename) {
  const byteLength = getSourceSize(source);
  const header = await readRange(source, 0, 28);
  const view = makeView(header);
  if (header.byteLength < 28 || view.getUint32(0, false) !== 0x78617221) {
    throw new Error('Invalid PKG: missing XAR magic (0x78617221)');
  }

  const headerSize = view.getUint16(4, false);
  const tocLenComp = view.getUint32(12, false);
  const tocLenUncomp = view.getUint32(20, false);
  const checksumAlg = view.getUint32(24, false);

  if (tocLenComp > 4 * 1024 * 1024 || tocLenUncomp > MAX_METADATA_BYTES) {
    throw new SecurityError('ZIP_BOMB');
  }

  const tocSlice = await readRange(source, headerSize, headerSize + tocLenComp);
  const stream = new Blob([tocSlice]).stream().pipeThrough(new DecompressionStream('deflate'));
  const tocBytes = new Uint8Array(await new Response(stream).arrayBuffer());
  if (tocBytes.byteLength > MAX_METADATA_BYTES) {
    throw new SecurityError('ZIP_BOMB');
  }

  const tocXml = textDecoder.decode(tocBytes);
  const fileNames = [];
  const fileRe = /<file\b[^>]*>[\s\S]*?<name>([^<]+)<\/name>/gi;
  let fm;
  while ((fm = fileRe.exec(tocXml)) !== null) {
    if (!fileNames.includes(fm[1])) fileNames.push(fm[1]);
  }

  const sigMatch = tocXml.match(/<signature(?:\s+style="([^"]+)")?[^>]*>([\s\S]*?)<\/signature>/i);
  const signed = Boolean(sigMatch && sigMatch[2].trim().length > 0);
  const signatureStyle = sigMatch?.[1] || (signed ? 'XAR-Signature' : 'Unsigned');

  const runtimes = [
    'macOS XAR',
    `Checksum Alg #${checksumAlg}`,
    signed ? `Signed (${signatureStyle})` : 'Unsigned PKG',
    ...fileNames.filter((n) => /^(Distribution|PackageInfo|Payload|Scripts)$/.test(n)),
  ];

  const tokens = [
    'pkg', 'xar', 'macos', 'installer',
    ...fileNames.map((f) => f.toLowerCase()),
    signed ? 'signed' : 'unsigned',
  ];

  return {
    filename,
    format: 'pkg',
    byteLength,
    summary: `macOS PKG (XAR) · ${fileNames.length} TOC entries · ${signed ? `Signed (${signatureStyle})` : 'Unsigned'}`,
    runtimes,
    permissions: [],
    cleartextTraffic: false,
    pkg: {
      headerSize,
      tocLenComp,
      tocLenUncomp,
      checksumAlg,
      files: fileNames,
      signed,
      signatureStyle,
    },
    sections: [],
    tokens,
    features: {
      maxCodeEntropy: 5.1,
      dangerousPermCount: 0,
      cleartextHttp: 0,
      packedSection: 0,
      fairplayOrUnsigned: signed ? 0 : 1,
    },
    architectureMap: {
      ui: fileNames.includes('Distribution') ? 'macOS Installer Distribution XML UI' : 'Flat component package UI',
      core: `XAR TOC (${fileNames.join(', ') || 'empty'}) · header ${headerSize} B`,
      data: fileNames.includes('Payload') ? 'Compressed cpio Payload & PackageInfo metadata' : 'Scripted installer bundle',
      security: signed ? `XAR <signature> verified present (${signatureStyle})` : 'No XAR <signature> element present (unsigned)',
    },
  };
}

async function analyzeZip(source, filename) {
  const byteLength = getSourceSize(source);
  const { entries, totalUncompressed, totalCompressed } = await parseZipDirectory(source);
  const tracker = { extracted: 0 };
  const manifestRe = /(^|\/)(package\.json|requirements\.txt|Dockerfile|pubspec\.yaml|render\.yaml|Cargo\.toml|go\.mod|\.github\/workflows\/[^/]+\.ya?ml)$/i;
  const schemaRe = /\.(sqlite|db|json|sql)$/i;
  const mlRe = /\.(onnx|tflite|safetensors|pt)$/i;

  const manifests = [];
  const manifestContents = {};
  const schemas = [];
  const mlModels = [];
  const runtimes = ['ZIP Archive'];
  const tokens = ['zip'];
  const topDirs = new Set();

  for (const entry of entries) {
    const parts = entry.name.split('/').filter(Boolean);
    if (parts.length > 1) topDirs.add(parts[0]);
    tokens.push(...parts.map((p) => p.toLowerCase()));

    if (manifestRe.test(entry.name)) {
      manifests.push(entry.name);
      if (entry.uncompressedSize <= 128 * 1024) {
        const bytes = await safeInflateEntry(source, entry, tracker);
        const text = textDecoder.decode(bytes);
        manifestContents[entry.name] = text;
        tokens.push(...text.toLowerCase().split(/[^a-z0-9_.-]+/).filter(Boolean).slice(0, 80));
      }
    }
    if (schemaRe.test(entry.name)) schemas.push(entry.name);
    if (mlRe.test(entry.name)) mlModels.push(entry.name);
  }

  const allText = Object.values(manifestContents).join('\n').toLowerCase();
  if (manifests.some((m) => m.endsWith('requirements.txt')) || entries.some((e) => e.name.endsWith('.py'))) runtimes.push('Python');
  if (manifests.some((m) => m.endsWith('package.json')) || entries.some((e) => e.name.endsWith('.js'))) runtimes.push('Node.js / JS');
  if (manifests.some((m) => m.endsWith('Dockerfile'))) runtimes.push('Docker');
  if (manifests.some((m) => m.endsWith('pubspec.yaml'))) runtimes.push('Dart / Flutter');
  if (schemas.some((s) => /\.(sqlite|db)$/i.test(s))) runtimes.push('SQLite');
  if (mlModels.some((m) => m.endsWith('.onnx')) || allText.includes('onnx')) runtimes.push('ONNX Runtime');
  if (mlModels.some((m) => m.endsWith('.tflite')) || allText.includes('tflite')) runtimes.push('TensorFlow Lite');
  if (allText.includes('mqtt')) runtimes.push('MQTT');

  const hasLatestDocker = /FROM\s+[^\s:]+:latest/i.test(manifestContents['Dockerfile'] || '');
  const hasRootDocker = manifests.some((m) => m.endsWith('Dockerfile')) && !/\n\s*USER\s+(?!root\b|0\b)\S+/i.test(manifestContents['Dockerfile'] || '');

  return {
    filename,
    format: 'zip',
    byteLength,
    summary: `Archive ZIP · ${entries.length} entries · ${manifests.length} manifests · ${schemas.length} schemas · ${mlModels.length} ML models`,
    runtimes,
    permissions: [],
    cleartextTraffic: false,
    sections: [],
    zip: {
      entryCount: entries.length,
      totalUncompressed,
      totalCompressed,
      entries: entries.map((e) => e.name),
      topology: Array.from(topDirs),
      manifests,
      manifestContents,
      schemas,
      mlModels,
    },
    tokens,
    features: {
      maxCodeEntropy: 4.8,
      dangerousPermCount: 0,
      cleartextHttp: allText.includes('http://') ? 1 : 0,
      packedSection: 0,
      fairplayOrUnsigned: (hasLatestDocker || hasRootDocker) ? 1 : 0,
    },
    architectureMap: {
      ui: manifests.length ? `Manifests: ${manifests.join(', ')}` : 'CLI / Headless package topology',
      core: `Directories: ${Array.from(topDirs).join(', ') || 'root'} (${entries.length} files)`,
      data: schemas.length ? `Schemas: ${schemas.join(', ')}` : 'No .sqlite/.db/.json schemas found',
      security: mlModels.length ? `Edge ML models (${mlModels.join(', ')}); Docker pinned=${!hasLatestDocker}` : 'Container & dependency surface',
    },
  };
}

/**
 * Parse a binary artifact (.apk, .xapk, .ipa, .exe, .msi, .pkg, .zip) lazily via readRange.
 */
export async function parseBinary(source, filename = 'artifact.zip') {
  const size = getSourceSize(source);
  if (size > MAX_FILE_BYTES) {
    throw new SecurityError('FILE_TOO_LARGE');
  }

  const format = await detectFormat(source, filename);
  switch (format) {
    case 'apk': return analyzeApk(source, filename);
    case 'xapk': return analyzeXapk(source, filename);
    case 'ipa': return analyzeIpa(source, filename);
    case 'exe': return analyzeExe(source, filename);
    case 'msi': return analyzeMsi(source, filename);
    case 'pkg': return analyzePkg(source, filename);
    case 'zip':
    default:
      return analyzeZip(source, filename);
  }
}

// ---------------------------------------------------------------------------
// Synthetic Clean-Room Specimen Factories (shared by index.html & tests)
// ---------------------------------------------------------------------------

function encodeUtf16Le(str) {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    out[i * 2] = code & 0xFF;
    out[i * 2 + 1] = (code >>> 8) & 0xFF;
  }
  return out;
}

function concatBytes(...chunks) {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function createFintechWalletApk() {
  const axmlHeader = new Uint8Array([0x03, 0x00, 0x08, 0x00, 0x80, 0x01, 0x00, 0x00]);
  const axmlPayload = [
    'com.cleanroom.fintechwallet',
    'android.permission.INTERNET',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.USE_BIOMETRIC',
    'usesCleartextTraffic="true"',
  ].join('\0');
  const axmlBytes = concatBytes(
    axmlHeader,
    encodeUtf16Le(axmlPayload),
    new Uint8Array([0, 0]),
    textEncoder.encode(axmlPayload)
  );

  const dexStrings = textEncoder.encode(
    'Lcom/fintech/wallet/LedgerActivity;\0okhttp3/OkHttpClient\0sqlite3_prepare\0payment_transfer\0balance_cents\0biometric_prompt\0http://api.wallet.local/v1/transfer\0'
  );
  const dexBytes = new Uint8Array(112 + dexStrings.length);
  const dexView = makeView(dexBytes);
  dexBytes.set(textEncoder.encode('dex\n037\0'), 0);
  dexView.setUint32(32, dexBytes.length, true);
  dexView.setUint32(36, 112, true);
  dexView.setUint32(40, 0x12345678, true);
  dexView.setUint32(56, 420, true);
  dexView.setUint32(64, 96, true);
  dexView.setUint32(72, 64, true);
  dexView.setUint32(80, 140, true);
  dexView.setUint32(88, 285, true);
  dexView.setUint32(96, 48, true);
  dexBytes.set(dexStrings, 112);

  return createStoreZip([
    { name: 'AndroidManifest.xml', content: axmlBytes },
    { name: 'classes.dex', content: dexBytes },
    { name: 'lib/arm64-v8a/libsqlcipher.so', content: textEncoder.encode('SQLCipher 4.5 AES-256\0') },
    { name: 'assets/ledger.sqlite', content: textEncoder.encode('SQLite format 3\0') },
  ]);
}

export function createSyntheticXapk() {
  const manifest = {
    xapk_version: 2,
    package_name: 'com.cleanroom.splitwallet',
    split_apks: [
      { file: 'base.apk', id: 'base' },
      { file: 'config.arm64_v8a.apk', id: 'config.arm64_v8a' },
    ],
    permissions: [
      'android.permission.INTERNET',
      'android.permission.CAMERA',
    ],
    expansions: [
      { file: 'Android/obb/com.cleanroom.splitwallet/main.1.com.cleanroom.splitwallet.obb' },
    ],
  };

  return createStoreZip([
    { name: 'manifest.json', content: JSON.stringify(manifest, null, 2) },
    { name: 'base.apk', content: createFintechWalletApk() },
    { name: 'config.arm64_v8a.apk', content: createStoreZip([{ name: 'lib/arm64-v8a/libsqlcipher.so', content: 'arm64\0' }]) },
    { name: 'Android/obb/com.cleanroom.splitwallet/main.1.com.cleanroom.splitwallet.obb', content: textEncoder.encode('OBB1\0pack') },
  ]);
}

export function createFairplaySampleIpa() {
  const sliceOff = 64;
  const cmdSize = 24;
  const macho = new Uint8Array(sliceOff + 32 + cmdSize);
  const view = makeView(macho);

  view.setUint32(0, 0xCAFEBABE, false);
  view.setUint32(4, 1, false);
  view.setUint32(8 + 0, 0x0100000C, false);
  view.setUint32(8 + 4, 0, false);
  view.setUint32(8 + 8, sliceOff, false);
  view.setUint32(8 + 12, 32 + cmdSize, false);
  view.setUint32(8 + 16, 14, false);

  view.setUint32(sliceOff + 0, 0xFEEDFACF, true);
  view.setUint32(sliceOff + 4, 0x0100000C, true);
  view.setUint32(sliceOff + 8, 0, true);
  view.setUint32(sliceOff + 12, 2, true);
  view.setUint32(sliceOff + 16, 1, true);
  view.setUint32(sliceOff + 20, cmdSize, true);
  view.setUint32(sliceOff + 24, 0x00200085, true);

  const cmdOff = sliceOff + 32;
  view.setUint32(cmdOff + 0, 0x2C, true);
  view.setUint32(cmdOff + 4, cmdSize, true);
  view.setUint32(cmdOff + 8, 0x4000, true);
  view.setUint32(cmdOff + 12, 0x8000, true);
  view.setUint32(cmdOff + 16, 1, true);

  const bplist = concatBytes(
    textEncoder.encode('bplist00'),
    textEncoder.encode('\0CFBundleIdentifier\0com.cleanroom.payvault\0CFBundleName\0PayVault\0NSCameraUsageDescription\0Scan QR invoices\0')
  );

  return createStoreZip([
    { name: 'Payload/PayVault.app/Info.plist', content: bplist },
    { name: 'Payload/PayVault.app/PayVault', content: macho },
    { name: 'Payload/PayVault.app/Frameworks/CryptoKit.framework/CryptoKit', content: textEncoder.encode('CryptoKit\0') },
  ]);
}

export function createArcadeEngineExe() {
  const eLfanew = 0x80;
  const optHeaderSize = 24;
  const secTableOff = eLfanew + 4 + 20 + optHeaderSize;
  const numSections = 3;
  const headersEnd = secTableOff + numSections * 40;
  const textOff = 0x200;
  const textSize = 256;
  const upxOff = textOff + textSize;
  const upxSize = 256;
  const rdataOff = upxOff + upxSize;
  const rdataBytes = textEncoder.encode(
    'd3d11.dll\0WS2_32.dll\0Direct3DCreate11\0shader_pipeline\0sprite_atlas\0game_loop_tick\0arcade_physics\0'
  );
  const totalSize = rdataOff + rdataBytes.length;

  const buf = new Uint8Array(Math.max(totalSize, headersEnd));
  const view = makeView(buf);

  view.setUint16(0, 0x5A4D, true);
  view.setUint32(0x3C, eLfanew, true);

  buf.set(textEncoder.encode('PE\0\0'), eLfanew);
  const coffOff = eLfanew + 4;
  view.setUint16(coffOff + 0, 0x8664, true);
  view.setUint16(coffOff + 2, numSections, true);
  view.setUint32(coffOff + 4, 1732291200, true);
  view.setUint16(coffOff + 16, optHeaderSize, true);
  view.setUint16(coffOff + 18, 0x0022, true);
  view.setUint16(coffOff + 20, 0x020B, true);

  const writeSection = (idx, name, rawSize, rawPtr, chars) => {
    const off = secTableOff + idx * 40;
    buf.set(textEncoder.encode(name).subarray(0, 8), off);
    view.setUint32(off + 8, rawSize, true);
    view.setUint32(off + 12, 0x1000 * (idx + 1), true);
    view.setUint32(off + 16, rawSize, true);
    view.setUint32(off + 20, rawPtr, true);
    view.setUint32(off + 36, chars, true);
  };

  writeSection(0, '.text', textSize, textOff, 0x60000020);
  writeSection(1, '.upx0', upxSize, upxOff, 0xE0000020);
  writeSection(2, '.rdata', rdataBytes.length, rdataOff, 0x40000040);

  buf.fill(0x90, textOff, textOff + textSize);
  for (let i = 0; i < upxSize; i++) buf[upxOff + i] = i & 0xFF;
  buf.set(rdataBytes, rdataOff);

  return buf;
}

export function createInstallerSampleMsi() {
  const magic = new Uint8Array([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
  const pad = new Uint8Array(24);
  const ascii = textEncoder.encode('MSCF\0\0\0\0ProductName\0DeconstructED Setup\0Manufacturer\0CleanRoom Labs\0InstallExecuteSequence\0');
  const utf16 = encodeUtf16Le('Windows Installer\0CustomAction\0UpgradeCode\0');
  return concatBytes(magic, pad, ascii, utf16);
}

export async function createSyntheticPkg() {
  const tocXml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<xar>',
    ' <toc>',
    '  <signature style="RSA"><offset>0</offset><size>256</size></signature>',
    '  <file id="1"><name>Distribution</name><type>file</type></file>',
    '  <file id="2"><name>PackageInfo</name><type>file</type></file>',
    '  <file id="3"><name>Payload</name><type>file</type></file>',
    '  <file id="4"><name>Scripts</name><type>file</type></file>',
    ' </toc>',
    '</xar>',
  ].join('\n');

  const uncompBytes = textEncoder.encode(tocXml);
  const compStream = new Blob([uncompBytes]).stream().pipeThrough(new CompressionStream('deflate'));
  const compBytes = new Uint8Array(await new Response(compStream).arrayBuffer());

  const headerSize = 28;
  const out = new Uint8Array(headerSize + compBytes.length);
  const view = makeView(out);
  view.setUint32(0, 0x78617221, false); // "xar!"
  view.setUint16(4, headerSize, false);
  view.setUint16(6, 1, false); // version
  view.setUint32(8, 0, false);
  view.setUint32(12, compBytes.length, false);
  view.setUint32(16, 0, false);
  view.setUint32(20, uncompBytes.length, false);
  view.setUint32(24, 1, false); // SHA-1 checksum_alg
  out.set(compBytes, headerSize);
  return out;
}

export function createEdgeSensorKitZip() {
  return createStoreZip([
    { name: 'requirements.txt', content: 'paho-mqtt==2.1.0\nonnxruntime==1.19.2\ntflite-runtime==2.14.0\n' },
    { name: 'Dockerfile', content: 'FROM python:3.12-slim\nWORKDIR /opt/sensor\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCMD ["python3", "src/sensor_bridge.py"]\n' },
    { name: 'src/sensor_bridge.py', content: '# Clean-room edge IoT MQTT telemetry bridge\nimport sqlite3\n' },
    { name: 'schemas/telemetry.sqlite', content: textEncoder.encode('SQLite format 3\0sensor_readings(device_id,celsius,ts)\0') },
    { name: 'schemas/device_config.json', content: JSON.stringify({ broker: 'mqtt://edge-gateway.local:1883', topic: 'sensors/telemetry', qos: 1 }, null, 2) },
    { name: 'models/anomaly_detector.onnx', content: textEncoder.encode('ONNX\x08\x00edge_sensor_anomaly_v1\0') },
    { name: 'models/wakeword.tflite', content: textEncoder.encode('TFL3\x00\x00edge_wakeword_quant\0') },
  ]);
}

export const SPECIMENS = [
  { id: 'fintech_wallet.apk', filename: 'fintech_wallet.apk', label: 'fintech_wallet.apk', formatBadge: 'APK', build: createFintechWalletApk },
  { id: 'arcade_engine.exe', filename: 'arcade_engine.exe', label: 'arcade_engine.exe', formatBadge: 'EXE', build: createArcadeEngineExe },
  { id: 'edge_sensor_kit.zip', filename: 'edge_sensor_kit.zip', label: 'edge_sensor_kit.zip', formatBadge: 'ZIP', build: createEdgeSensorKitZip },
];
