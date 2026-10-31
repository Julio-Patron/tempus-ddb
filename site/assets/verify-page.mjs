// Public evidence verifier. Everything runs in this page: the verifier is the wasm32
// build of the Tempus crate (assets/wasm/), the gate public key is pinned by the reader,
// and nothing is sent anywhere. The only fetches are same-origin sample files.
import init, * as verifier from './wasm/tempus_verifier.js';

const form = document.querySelector('#verify-form');
const fileInput = document.querySelector('#evidence-file');
const evidenceText = document.querySelector('#evidence-text');
const keyInput = document.querySelector('#gate-key');
const executorInput = document.querySelector('#executor-keys');
const verifyButton = document.querySelector('#verify-button');
const sampleButton = document.querySelector('#load-sample');
const tamperedButton = document.querySelector('#load-tampered');
const clearButton = document.querySelector('#clear-form');
const badge = document.querySelector('#result-badge');
const status = document.querySelector('#verification-status');
const summary = document.querySelector('#evidence-summary');
const checks = document.querySelector('#evidence-checks');
const errors = document.querySelector('#evidence-errors');
const notChecked = document.querySelector('#not-checked');
const linkPanel = document.querySelector('#link-panel');
const engine = document.querySelector('#engine-version');
const resultJson = document.querySelector('#result-json');

const CHECK_TITLES = {
  authorization: ['Permit', 'The gate signed this exact permit (intent hash, decision, policy digest, expiry) with the pinned key, and the agent signed the intent.'],
  execution: ['Outcome', 'The gate signed this exact outcome receipt with the pinned key, bound to the permit, and the executor signed the outcome.'],
  checkpoint: ['Ledger inclusion', 'A gate-signed checkpoint covers an event stream that contains this permit and outcome, with no gaps or rollback.'],
};
const CHECK_STATES = {
  VERIFIED: ['pass', '✓', 'PASS'],
  FAILED: ['fail', '×', 'FAIL'],
  INVALID: ['fail', '×', 'FAIL'],
  NOT_PRESENT: ['neutral', '–', 'NOT PRESENT'],
};
const NOT_CHECKED = {
  AGENT_REGISTRATION_AT_ISSUE: 'Whether the agent was registered and active when the permit was issued. The gate attests it with its signature; this page does not re-check the registry.',
  SINGLE_USE_CONSUMPTION: 'That this permit produced exactly one outcome. No document can show that; only the gate’s ledger can.',
  EXECUTOR_IDENTITY: 'Which executor carried out the action. The gate attests it; pin the executor public key above to check it here.',
  LEDGER_INCLUSION: 'That these events are in the gate’s signed ledger. This file carries no checkpoint, so inclusion is not shown.',
  COMPLETENESS: 'That nothing else happened: other actions, retries or outcomes. No single file can show that; compare against the ledger or a checkpoint.',
};
const ERROR_TEXT = {
  AUTHORIZATION_ID_MISMATCH: 'The permit’s content no longer matches its own identifier: a signed field was edited after signing.',
  AUTHORIZATION_SIGNATURE_INVALID: 'The gate signature on the permit does not verify with the pinned key.',
  AUTHORIZATION_GATE_KEY_NOT_PINNED: 'The permit was signed by a different gate than the key you pinned.',
  INTENT_HASH_MISMATCH: 'The intent in the file is not the intent the permit was issued for.',
  AGENT_SIGNATURE_INVALID: 'The agent signature on the intent does not verify.',
  RECEIPT_ID_MISMATCH: 'The outcome receipt’s content no longer matches its own identifier.',
  EXECUTION_SIGNATURE_INVALID: 'The gate signature on the outcome receipt does not verify with the pinned key.',
  EXECUTION_GATE_KEY_NOT_PINNED: 'The outcome receipt was signed by a different gate than the key you pinned.',
  EXECUTOR_SIGNATURE_INVALID: 'The executor signature on the outcome does not verify.',
  EXECUTOR_KEY_NOT_PINNED: 'The executor that signed is not one of the executor keys you pinned.',
  OUTCOME_HASH_MISMATCH: 'The outcome in the file is not the outcome the receipt was issued for.',
  BUNDLE_VERIFY_URL_MISMATCH: 'The verify link inside the file names a different bundle: the file changed after the link was written, or the link belongs to another file.',
  BUNDLE_VERIFY_URL_INVALID: 'The verify link inside the file is not a verifier address with a bundle digest.',
  BUNDLE_ACTION_ID_MISMATCH: 'The bundle’s action identifier differs from the permit’s.',
  TRACE_ACTION_ID_MISMATCH: 'The trace’s action identifier differs from the signed one.',
  POLICY_DIGEST_MISMATCH: 'The policy bundle in the file is not the policy the permit cites.',
  POLICY_SIGNATURE_INVALID: 'The policy bundle’s gate signature does not verify.',
  DUPLICATE_JSON_KEY: 'The file repeats a JSON key, so different readers would see different values. Refused.',
  NON_EXACT_NUMBER: 'The file holds a number that is not an exact integer, so its hash is ambiguous. Refused.',
};

let ready = false;
let fragment = parseFragment();

function parseFragment() {
  const params = new URLSearchParams(location.hash.replace(/^#/, ''));
  return {
    action: params.get('action'),
    bundle: params.get('bundle'),
    gate: params.get('gate'),
  };
}

function setBadge(state) {
  badge.textContent = state;
  badge.className = `badge ${state === 'VERIFIED' ? '' : state === 'INVALID' || state === 'ERROR' ? 'danger' : state === 'READY' || state === 'LOADING' ? 'neutral' : 'warn'}`;
}
function setStatus(state, message) {
  status.textContent = message;
  status.dataset.state = state;
  setBadge(state);
}
function row(label, value, mono = true) {
  const item = document.createElement('div');
  item.className = 'metric';
  const name = document.createElement('span');
  const detail = document.createElement('strong');
  name.textContent = label;
  detail.textContent = value ?? '—';
  if (!mono) detail.style.fontFamily = 'inherit';
  item.append(name, detail);
  return item;
}
function listItem(title, detail, state) {
  const item = document.createElement('div');
  item.className = `check ${state}`;
  const icon = document.createElement('span');
  icon.className = 'check-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = state === 'pass' ? '✓' : state === 'fail' ? '×' : state === 'warn' ? '!' : '–';
  const copy = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = title;
  const span = document.createElement('span');
  span.className = 'check-detail';
  span.textContent = detail;
  copy.append(strong, span);
  item.append(icon, copy);
  return item;
}

function normalizeKey(raw, label) {
  const text = raw.trim();
  if (!text) return '';
  if (text.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(text); } catch { throw new Error(`${label}: not a public key (64 hex characters) and not valid JSON.`); }
    if (parsed && typeof parsed === 'object' && 'private_key' in parsed) {
      throw new Error(`${label}: that text contains a PRIVATE key. Never paste a key file here; paste only the public_key value. Nothing was sent, but rotate that key if it has left your machine.`);
    }
    const candidate = parsed?.public_key ?? parsed?.gate_public_key ?? parsed?.gate_id;
    if (typeof candidate !== 'string') throw new Error(`${label}: JSON has no public_key field.`);
    return normalizeKey(candidate, label);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error(`${label}: a public key is exactly 64 hexadecimal characters.`);
  return text.toLowerCase();
}
function normalizeExecutorKeys(raw) {
  const parts = raw.split(/[\s,]+/).filter(Boolean);
  return parts.map((part, index) => normalizeKey(part, `Executor key ${index + 1}`));
}

function detectKind(document) {
  switch (document?.schema_version) {
    case 'tempus.evidence-bundle.v1': return 'bundle';
    case 'tempus.action-trace.v1': return 'trace';
    case 'tempus.authorization-result.v1': return 'authorization';
    case 'tempus.execution-result.v1': return 'execution';
    default: return null;
  }
}

function renderResult(result, evidence, kind) {
  const verdict = result.status;
  const phaseText = { AUTHORIZED: 'permit issued, no outcome in this file', COMPLETED: 'permit issued and outcome recorded', EXPIRED: 'permit expired without an outcome in this file', BLOCKED: 'the gate signed a denial' };
  const message = verdict === 'VERIFIED'
    ? `Every signed document in this file checks out against the pinned gate key. Phase: ${result.phase} (${phaseText[result.phase] ?? result.phase}).`
    : 'This file is not valid evidence. At least one signed document does not match, or the file was changed after signing.';
  setStatus(verdict, message);

  summary.replaceChildren(
    row('Document', kind === 'bundle' ? 'Evidence bundle' : kind === 'trace' ? 'Action trace' : kind === 'authorization' ? 'Permit' : 'Outcome', false),
    row('Action ID', result.action_id),
    row('Decision', result.decision ?? '—'),
    row('Phase', result.phase ?? '—'),
    row('Outcome', result.execution_status ?? 'not in file'),
    row('Gate key (pinned)', result.trust.gate_public_key),
    row('Executor keys pinned', String(result.trust.executor_keys_pinned ?? 0)),
  );
  if (result.bundle_digest) summary.append(row('Bundle digest', result.bundle_digest));

  checks.replaceChildren();
  for (const [name, [title, detail]] of Object.entries(CHECK_TITLES)) {
    const value = result.checks?.[name];
    if (value === undefined) continue;
    const [state, , label] = CHECK_STATES[value] ?? ['warn', '!', value];
    checks.append(listItem(`${title} · ${label}`, value === 'NOT_PRESENT' ? `${title.toLowerCase()} is not in this file.` : detail, state));
  }
  if (result.output_degraded === true) {
    checks.append(listItem('Executor output was degraded', 'The executor could not represent its full result; the receipt says so and the verifier reports it.', 'warn'));
  }

  errors.replaceChildren();
  errors.hidden = !(result.errors?.length);
  for (const code of result.errors ?? []) {
    const key = code.split(' ')[0];
    errors.append(listItem(key, ERROR_TEXT[key] ?? `Reported by the verifier as ${code}.`, 'fail'));
  }

  notChecked.replaceChildren();
  for (const entry of result.trust?.not_checked ?? []) {
    const code = String(entry).split(' ')[0];
    notChecked.append(listItem(code.replaceAll('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase()), NOT_CHECKED[code] ?? String(entry), 'neutral'));
  }

  renderLink(result, evidence, kind);
  resultJson.textContent = JSON.stringify(result, null, 2);
}

function renderLink(result, evidence, kind) {
  linkPanel.replaceChildren();
  const items = [];
  if (fragment.bundle) {
    const match = result.bundle_digest && fragment.bundle.toLowerCase() === result.bundle_digest;
    items.push(listItem(
      match ? 'This link names the loaded file' : 'This link names a different file',
      match
        ? `The link you followed carries bundle digest ${fragment.bundle.slice(0, 16)}…, and the loaded bundle has that digest.`
        : `The link carries bundle digest ${fragment.bundle.slice(0, 16)}… but the loaded ${kind === 'bundle' ? 'bundle has digest ' + (result.bundle_digest ?? '?').slice(0, 16) + '…' : 'document is not a bundle'}. Ask for the file this link was issued for.`,
      match ? 'pass' : 'fail',
    ));
  }
  if (fragment.action) {
    const match = fragment.action === result.action_id;
    items.push(listItem(
      match ? 'This link is for the loaded action' : 'This link is for another action',
      match ? 'The action identifier in the link equals the signed action identifier in the file.' : `The link names action ${fragment.action.slice(0, 16)}… and the file is about ${String(result.action_id).slice(0, 16)}….`,
      match ? 'pass' : 'fail',
    ));
  }
  const embedded = evidence?.verify_url ?? evidence?.authorization?.verify_url ?? evidence?.authorization?.authorization?.verify_url ?? evidence?.receipt?.verify_url;
  if (embedded) {
    items.push(listItem('Verifier named by the file', `${embedded.split('#')[0]} — if that is not this page, the issuer points at another verifier; both must agree on the same spec.`, 'neutral'));
  }
  linkPanel.hidden = items.length === 0;
  linkPanel.append(...items);
}

async function readEvidenceText() {
  const file = fileInput.files?.[0];
  if (file) return file.text();
  return evidenceText.value;
}

async function runVerification(event) {
  event?.preventDefault();
  if (!ready) return;
  errors.hidden = true;
  let text;
  try {
    text = (await readEvidenceText()).trim();
    if (!text) throw new Error('Choose an evidence file or paste its JSON.');
    const gate = normalizeKey(keyInput.value, 'Gate public key');
    if (!gate) throw new Error('Paste the gate PUBLIC key you obtained out of band (64 hex characters). Without a pinned key nothing here is independent.');
    const executors = normalizeExecutorKeys(executorInput.value);
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = null; }
    const kind = detectKind(parsed);
    const raw = kind === 'bundle'
      ? verifier.verify_bundle(text, gate, JSON.stringify(executors))
      : verifier.verify_receipt(text, gate, JSON.stringify(executors));
    const result = JSON.parse(raw);
    renderResult(result, parsed, kind ?? result.kind);
  } catch (error) {
    const message = String(error?.message ?? error);
    setStatus('ERROR', message.replace(/^Error:\s*/, ''));
    summary.replaceChildren();
    checks.replaceChildren();
    notChecked.replaceChildren();
    linkPanel.hidden = true;
    resultJson.textContent = '';
  }
}

async function loadSample(name) {
  try {
    const [bundle, key] = await Promise.all([
      fetch(`data/evidence/${name}`).then((response) => { if (!response.ok) throw new Error(`Sample ${name} unavailable (${response.status}).`); return response.text(); }),
      fetch('data/evidence/gate_public_key.txt').then((response) => { if (!response.ok) throw new Error('Sample key unavailable.'); return response.text(); }),
    ]);
    fileInput.value = '';
    evidenceText.value = bundle.trim();
    keyInput.value = key.trim();
    executorInput.value = '';
    await runVerification();
  } catch (error) {
    setStatus('ERROR', String(error?.message ?? error));
  }
}

function clearForm() {
  form.reset();
  summary.replaceChildren();
  checks.replaceChildren();
  errors.replaceChildren();
  errors.hidden = true;
  notChecked.replaceChildren();
  linkPanel.hidden = true;
  resultJson.textContent = '';
  setStatus('READY', 'Load a file and pin the gate public key to verify.');
}

form.addEventListener('submit', runVerification);
sampleButton.addEventListener('click', () => loadSample('bundle.json'));
tamperedButton.addEventListener('click', () => loadSample('bundle_tampered_decision.json'));
clearButton.addEventListener('click', clearForm);
fileInput.addEventListener('change', () => { if (fileInput.files?.length) evidenceText.value = ''; });
window.addEventListener('hashchange', () => { fragment = parseFragment(); describeFragment(); });

function describeFragment() {
  const intro = document.querySelector('#link-intro');
  if (fragment.bundle) {
    intro.hidden = false;
    intro.textContent = `This link was issued for one evidence bundle (digest ${fragment.bundle.slice(0, 16)}…). Load that file and the gate public key you were given; the page checks that they belong together.`;
  } else if (fragment.action) {
    intro.hidden = false;
    intro.textContent = `This link was issued for action ${fragment.action.slice(0, 16)}…. Load the permit, outcome, trace or bundle for it and the gate public key you were given.`;
  } else {
    intro.hidden = true;
  }
  if (fragment.gate && !keyInput.value) {
    try { keyInput.value = normalizeKey(fragment.gate, 'Gate public key'); } catch { /* ignore a malformed hint */ }
  }
}

try {
  setStatus('LOADING', 'Loading the verifier…');
  await init(new URL('./wasm/tempus_verifier_bg.wasm', import.meta.url));
  ready = true;
  engine.textContent = `Verifier: tempus-ddb ${verifier.version()} (WebAssembly, this page only)`;
  verifyButton.disabled = false;
  sampleButton.disabled = false;
  tamperedButton.disabled = false;
  describeFragment();
  setStatus('READY', 'Load a file and pin the gate public key to verify.');
} catch (error) {
  setStatus('ERROR', `The verifier could not load in this browser (${String(error?.message ?? error)}). Use the CLI: tempus verify-bundle --bundle evidence.json --gate-public-key <hex>.`);
}
