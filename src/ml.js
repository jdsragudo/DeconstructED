const memMap = new Map();
const memStore = {
  getItem(key) {
    return memMap.has(key) ? memMap.get(key) : null;
  },
  setItem(key, value) {
    memMap.set(key, String(value));
  },
  removeItem(key) {
    memMap.delete(key);
  },
};

export function getStore() {
  try {
    if (typeof localStorage !== 'undefined' && localStorage !== null) return localStorage;
  } catch {}
  return memStore;
}

export const BKT_KEY = 'deconstructed_bkt_v1';
export const P_L0 = 0.25;
export const P_T = 0.30;
export const P_G = 0.15;
export const P_S = 0.10;

export const ARCHETYPES = [
  'Fintech / Payments',
  '2D/3D Game',
  'Media & Camera',
  'IoT / Hardware',
  'Productivity / Utility',
];

// Curated multinomial archetype lexicon (clean-room TF-IDF + Naive Bayes)
const ARCHETYPE_LEXICON = {
  'Fintech / Payments': {
    fintech: 4.0,
    wallet: 4.0,
    payment: 3.8,
    ledger: 3.4,
    biometric: 3.2,
    use_biometric: 3.0,
    sqlcipher: 3.0,
    okhttp: 2.2,
    balance: 2.8,
    transfer: 2.8,
    cryptokit: 2.6,
    payvault: 3.2,
    sqlite: 1.8,
    read_contacts: 1.5,
    cleartext_http: 1.4,
    apk: 1.0,
  },
  '2D/3D Game': {
    d3d11: 4.2,
    direct3d: 3.8,
    directx: 3.8,
    shader: 3.6,
    sprite: 3.6,
    arcade: 3.8,
    game: 3.5,
    unity: 3.6,
    libunity: 3.8,
    libil2cpp: 3.8,
    libgodot: 3.8,
    ws2_32: 2.6,
    upx0: 2.4,
    packed_section: 2.0,
    physics: 2.8,
    exe: 1.2,
  },
  'Media & Camera': {
    camera: 4.0,
    nscamerausagedescription: 4.0,
    ffmpeg: 3.8,
    avfoundation: 3.6,
    exo: 3.2,
    exoplayer: 3.4,
    video: 3.4,
    audio: 3.0,
    codec: 3.2,
    record_audio: 3.2,
    gallery: 2.8,
    photo: 2.8,
    microphone: 2.6,
    webrtc: 2.6,
  },
  'IoT / Hardware': {
    mqtt: 4.2,
    paho: 3.6,
    sensor: 4.0,
    iot: 4.0,
    edge: 3.4,
    telemetry: 3.8,
    onnx: 3.4,
    onnxruntime: 3.6,
    tflite: 3.4,
    device: 2.8,
    ble: 3.2,
    bluetooth: 3.2,
    serial: 2.8,
    dockerfile: 1.8,
    requirements: 1.4,
    python: 1.6,
    sqlite: 1.5,
  },
  'Productivity / Utility': {
    msi: 3.6,
    ole2: 3.2,
    installer: 3.4,
    productname: 3.0,
    manufacturer: 2.8,
    electron: 2.8,
    document: 3.0,
    calendar: 3.0,
    notes: 3.0,
    editor: 2.8,
    office: 3.0,
    utility: 3.2,
    package: 1.6,
    cli: 2.2,
    pkg: 3.4,
    xar: 3.4,
    distribution: 3.0,
    packageinfo: 3.0,
    scripts: 2.2,
    signature: 2.0,
  },
};

function expandTokens(rawTokens) {
  const expanded = [];
  for (const raw of rawTokens || []) {
    const lower = String(raw).toLowerCase().trim();
    if (!lower) continue;
    expanded.push(lower);
    const parts = lower.split(/[^a-z0-9]+/).filter((p) => p.length >= 2);
    for (const part of parts) {
      if (part !== lower) expanded.push(part);
    }
  }
  return expanded;
}

const VOCAB = (() => {
  const docFreq = new Map();
  for (const arch of ARCHETYPES) {
    const terms = Object.keys(ARCHETYPE_LEXICON[arch]);
    for (const term of terms) {
      docFreq.set(term, (docFreq.get(term) || 0) + 1);
    }
  }
  const idf = new Map();
  const nDocs = ARCHETYPES.length;
  for (const [term, df] of docFreq.entries()) {
    idf.set(term, Math.log((1 + nDocs) / (1 + df)) + 1);
  }
  return { terms: Array.from(docFreq.keys()), idf };
})();

/**
 * Classify an artifact into one of 5 archetypes using pure-JS TF-IDF + Multinomial Naive Bayes.
 * Uses Laplace smoothing and max-shift log-sum-exp softmax.
 * @param {string[]} tokens
 * @returns {{ topArchetype: string, probabilities: Record<string, number> }}
 */
export function classifyArchetype(tokens) {
  const expanded = expandTokens(tokens);
  const tf = new Map();
  for (const t of expanded) {
    tf.set(t, (tf.get(t) || 0) + 1);
  }

  const vocabSize = VOCAB.terms.length;
  const alpha = 1.0;

  const logScores = ARCHETYPES.map((arch) => {
    const weights = ARCHETYPE_LEXICON[arch];
    const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);
    const denom = totalWeight + alpha * vocabSize;
    let logProb = Math.log(1 / ARCHETYPES.length);

    for (const [term, count] of tf.entries()) {
      const idf = VOCAB.idf.get(term);
      if (!idf) continue;
      const w = weights[term] || 0;
      const condProb = (w + alpha) / denom;
      const tfIdfWeight = (1 + Math.log(count)) * idf;
      logProb += tfIdfWeight * Math.log(condProb);
    }
    return logProb;
  });

  // Max-shift log-sum-exp softmax for numerical stability
  const m = Math.max(...logScores);
  const exps = logScores.map((s) => Math.exp(s - m));
  const sumExp = exps.reduce((a, b) => a + b, 0);

  const probabilities = {};
  let topArchetype = ARCHETYPES[0];
  let bestProb = -1;

  ARCHETYPES.forEach((arch, idx) => {
    const p = exps[idx] / sumExp;
    probabilities[arch] = p;
    if (p > bestProb) {
      bestProb = p;
      topArchetype = arch;
    }
  });

  return { topArchetype, probabilities };
}

function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

function computeLogit(f) {
  const entropyExcess = Math.max(0, (Number(f.maxCodeEntropy) || 0) - 5.0);
  const perms = Math.min(6, Math.max(0, Number(f.dangerousPermCount) || 0));
  const cleartext = f.cleartextHttp ? 1 : 0;
  const packed = f.packedSection ? 1 : 0;
  const unsigned = f.fairplayOrUnsigned ? 1 : 0;

  return (
    -2.1 +
    entropyExcess * 0.48 +
    perms * 0.65 +
    cleartext * 1.35 +
    packed * 1.45 +
    unsigned * 0.65
  );
}

/**
 * Explainable weighted logistic risk scoring over 5 static binary features.
 * @param {object} features
 * @returns {{ score: number, level: string, attributions: Array<{feature: string, value: number, delta: number}> }}
 */
export function scoreRisk(features = {}) {
  const normalized = {
    maxCodeEntropy: Number(features.maxCodeEntropy) || 0,
    dangerousPermCount: Number(features.dangerousPermCount) || 0,
    cleartextHttp: features.cleartextHttp ? 1 : 0,
    packedSection: features.packedSection ? 1 : 0,
    fairplayOrUnsigned: features.fairplayOrUnsigned ? 1 : 0,
  };

  const fullScore = sigmoid(computeLogit(normalized)) * 100;
  const score = Math.round(fullScore);
  const level = score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';

  const featureKeys = [
    'maxCodeEntropy',
    'dangerousPermCount',
    'cleartextHttp',
    'packedSection',
    'fairplayOrUnsigned',
  ];

  const attributions = featureKeys.map((key) => {
    const baselineVal = key === 'maxCodeEntropy' ? 5.0 : 0;
    const ablated = { ...normalized, [key]: baselineVal };
    const ablatedScore = sigmoid(computeLogit(ablated)) * 100;
    const delta = Number((fullScore - ablatedScore).toFixed(1));
    return {
      feature: key,
      value: Number(normalized[key].toFixed ? normalized[key].toFixed(2) : normalized[key]),
      delta,
    };
  }).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

  return { score, level, attributions };
}

/**
 * Bayesian Knowledge Tracing update.
 * @param {number} prior
 * @param {boolean} passed
 * @returns {number}
 */
export function updateBKT(prior, passed) {
  const p = Math.min(0.9999, Math.max(0.0001, typeof prior === 'number' ? prior : P_L0));
  let pPost;
  if (passed) {
    const num = p * (1 - P_S);
    const den = num + (1 - p) * P_G;
    pPost = num / den;
  } else {
    const num = p * P_S;
    const den = num + (1 - p) * (1 - P_G);
    pPost = num / den;
  }
  const pNext = pPost + (1 - pPost) * P_T;
  return Number(Math.min(0.9999, Math.max(0.0001, pNext)).toFixed(6));
}

export function loadMasteryMap() {
  const defaults = {
    permission_hardening: P_L0,
    sqlite_safety: P_L0,
    api_bounds: P_L0,
    docker_hardening: P_L0,
  };
  try {
    const raw = getStore().getItem(BKT_KEY);
    if (!raw) return { ...defaults };
    const parsed = JSON.parse(raw);
    return { ...defaults, ...parsed };
  } catch {
    return { ...defaults };
  }
}

export function saveMasteryMap(map) {
  try {
    getStore().setItem(BKT_KEY, JSON.stringify(map));
  } catch {}
  return map;
}

export function recordSkillAttempt(skillId, passed) {
  const map = loadMasteryMap();
  const prior = typeof map[skillId] === 'number' ? map[skillId] : P_L0;
  const next = updateBKT(prior, Boolean(passed));
  map[skillId] = next;
  saveMasteryMap(map);
  return { prior, next, masteryMap: map };
}

/**
 * Run full ML pipeline (archetype classification + explainable risk scoring) on a scanResult.
 * @param {object} scanResult
 * @returns {{ topArchetype: string, probabilities: Record<string, number>, risk: object }}
 */
export function analyzeWithML(scanResult) {
  const { topArchetype, probabilities } = classifyArchetype(scanResult?.tokens || []);
  const risk = scoreRisk(scanResult?.features || {});
  return { topArchetype, probabilities, risk };
}
