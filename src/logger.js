'use strict';

/**
 * Zero-dependency structured logger for the engine -- colored, component-tagged, with
 * first-class hex dump support.
 *
 * ── WHY THE ENGINE LOGS AT ALL ───────────────────────────────────────────────────────────
 * A storage engine that fails silently is the worst kind to operate. The failure that
 * motivated this module -- a range query that spun for two minutes inside one synchronous
 * loop while every other client sat behind a blocked event loop -- produced *no output at
 * all*. Nothing in the process said what it was doing, so from the outside the database
 * looked hung rather than busy, and the only visible remedy was deleting the data
 * directory. Every expensive or lossy decision the engine makes now says so.
 *
 * ── TWO CALL SHAPES, ON PURPOSE ──────────────────────────────────────────────────────────
 * Both of these work and mean the same thing:
 *
 *     log.info('collection opened', { records: 12 })
 *     log.info({ msg: 'collection opened', records: 12 })
 *
 * The second is the shape @fitfak/smtp's logger uses. Accepting it is what lets a host
 * application pass its own logger straight in via setSink() and get engine lines
 * interleaved with its own, in its own format, instead of running two loggers that
 * disagree about levels and destinations.
 */

const LEVELS = { TRACE: 10, DEBUG: 20, INFO: 30, WARN: 40, ERROR: 50, SILENT: 99 };

const LEVEL_COLORS = {
  TRACE: '\x1b[90m', DEBUG: '\x1b[36m', INFO: '\x1b[32m',
  WARN: '\x1b[33m', ERROR: '\x1b[31m',
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

// FITDB_LOG_LEVEL is the name that belongs to this package; DTLS_LOG_LEVEL is honoured too
// so a process already running with the sibling transport's logger turned up does not have
// to set two variables to see the same depth of detail.
const envLevel = String(process.env.FITDB_LOG_LEVEL || process.env.DTLS_LOG_LEVEL || 'INFO').toUpperCase();
let minLevel = LEVELS[envLevel] ?? LEVELS.INFO;

let colorEnabled = !!process.stdout.isTTY && process.env.NO_COLOR !== '1';
let jsonMode = String(process.env.FITDB_LOG_JSON || '') === '1';

// When set, every line is handed to this object instead of being written to stdout/stderr.
// Expected surface: { trace, debug, info, warn, error } taking (fields) or (msg, fields).
let sink = null;

function c(code) { return colorEnabled && !jsonMode ? code : ''; }

function ts() { return new Date().toISOString().slice(11, 23); } // HH:MM:SS.mmm

/**
 * Keys whose values never reach a log line, at any level.
 *
 * "We only print it at trace" is not protection: the person who turns trace on is chasing a
 * problem, and the first thing they do with the output is paste it somewhere. A wrapped DDK
 * or a client secret in that paste is a key compromise, so these are masked unconditionally.
 */
const SECRET_KEY_RE = /(secret|password|passwd|token|authorization|cookie|privatekey|apikey|api_key|ddk|kek)/i;

function maskSecret(value) {
  const s = String(value == null ? '' : value);
  if (!s) return '';
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length}b)`;
}

function bufReplacer(_k, v) {
  if (Buffer.isBuffer(v)) {
    const head = v.toString('hex').slice(0, 48);
    return `<Buffer ${v.length}B 0x${head}${v.length > 24 ? '…' : ''}>`;
  }
  if (typeof v === 'bigint') return v.toString();
  return v;
}

function safeJson(o) {
  try { return JSON.stringify(o, bufReplacer); } catch { return String(o); }
}

/** Normalizes both call shapes into one `{ msg, ...fields }` object. */
function coerce(a, b) {
  if (a instanceof Error) return { error: a.message, stack: a.stack, ...(b && typeof b === 'object' ? b : {}) };
  if (typeof a === 'string') return { msg: a, ...(b && typeof b === 'object' ? b : {}) };
  if (a && typeof a === 'object') return { ...a, ...(b && typeof b === 'object' ? b : {}) };
  return { msg: String(a == null ? '' : a) };
}

function redact(fields) {
  const out = {};
  for (const [k, v] of Object.entries(fields || {})) {
    if (v === undefined) continue;
    if (SECRET_KEY_RE.test(k)) { out[k] = (v && typeof v === 'object' && !Buffer.isBuffer(v)) ? '[redacted]' : maskSecret(v); continue; }
    out[k] = v instanceof Error ? v.message : v;
  }
  return out;
}

function stringifyRest(fields) {
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    if (k === 'msg') continue;
    if (v === null) { parts.push(`${k}=null`); continue; }
    if (Buffer.isBuffer(v)) { parts.push(`${k}=<${v.length}B>`); continue; }
    if (typeof v === 'object') { parts.push(`${k}=${safeJson(v)}`); continue; }
    const s = String(v);
    parts.push(/[\s"=]/.test(s) ? `${k}="${s.replace(/"/g, '\\"')}"` : `${k}=${s}`);
  }
  return parts.join(' ');
}

function hexDump(buf, { width = 16, indent = '  ', maxBytes = 512 } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return `${indent}<empty>`;
  const view = buf.length > maxBytes ? buf.subarray(0, maxBytes) : buf;
  const out = [];
  for (let i = 0; i < view.length; i += width) {
    const slice = view.subarray(i, i + width);
    const hex = [...slice].map((b) => b.toString(16).padStart(2, '0'))
      .join(' ').padEnd(width * 3 - 1, ' ');
    const ascii = [...slice].map((b) => ((b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.')).join('');
    const off = i.toString(16).padStart(6, '0');
    out.push(`${indent}${c(DIM)}${off}${c(RESET)}  ${hex}  ${c(DIM)}|${ascii}|${c(RESET)}`);
  }
  if (buf.length > maxBytes) out.push(`${indent}${c(DIM)}… ${buf.length - maxBytes} more bytes${c(RESET)}`);
  return out.join('\n');
}

function emit(levelName, component, fields) {
  if (LEVELS[levelName] < minLevel) return;
  const norm = redact(fields);

  if (sink) {
    const method = levelName.toLowerCase();
    const fn = typeof sink[method] === 'function' ? sink[method] : sink.info;
    if (typeof fn === 'function') fn.call(sink, { component, ...norm });
    return;
  }

  const stream = LEVELS[levelName] >= LEVELS.WARN ? process.stderr : process.stdout;

  if (jsonMode) {
    stream.write(`${safeJson({ ts: new Date().toISOString(), level: levelName, component, ...norm })}\n`);
    return;
  }

  const color = c(LEVEL_COLORS[levelName] || '');
  const head = `${c(DIM)}${ts()}${c(RESET)} ${color}${c(BOLD)}${levelName.padEnd(5)}${c(RESET)} ${color}[${component}]${c(RESET)}`;
  const message = norm.msg != null ? ` ${norm.msg}` : '';
  const rest = stringifyRest(norm);
  stream.write(`${head}${message}${rest ? ` ${c(DIM)}${rest}${c(RESET)}` : ''}\n`);
}

/** Builds a logger bound to `component`. */
function mk(component) {
  const self = {
    trace: (a, b) => emit('TRACE', component, coerce(a, b)),
    debug: (a, b) => emit('DEBUG', component, coerce(a, b)),
    info: (a, b) => emit('INFO', component, coerce(a, b)),
    warn: (a, b) => emit('WARN', component, coerce(a, b)),
    error: (a, b) => emit('ERROR', component, coerce(a, b)),
    child: (sub) => mk(`${component}:${sub}`),
    enabled: (lvl) => (LEVELS[String(lvl).toUpperCase()] ?? 0) >= minLevel,

    hex: (label, buf) => {
      if (LEVELS.DEBUG < minLevel) return;
      emit('DEBUG', component, { msg: label, bytes: Buffer.isBuffer(buf) ? buf.length : 0 });
      if (!sink && !jsonMode) process.stdout.write(`${hexDump(buf)}\n`);
    },

    /**
     * Duration probe: `const done = log.timer('replay'); … done({ records: 40 })`.
     *
     * Reports at DEBUG normally, but escalates to WARN past `warnAboveMs`. That escalation is
     * the point -- an operation that quietly got 100x slower is exactly the kind of thing
     * nobody goes looking for until it has already taken the process down.
     */
    timer: (label, { warnAboveMs = 1000 } = {}) => {
      const startedAt = process.hrtime.bigint();
      return (fields = {}) => {
        const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
        const rounded = Math.round(ms * 100) / 100;
        emit(ms >= warnAboveMs ? 'WARN' : 'DEBUG', component, { msg: label, ms: rounded, ...fields });
        return rounded;
      };
    },
  };
  return self;
}

function setLevel(name) {
  const n = LEVELS[String(name).toUpperCase()];
  if (n == null) throw new Error(`fitdb: unknown log level: ${name}`);
  minLevel = n;
  return name;
}

function getLevel() {
  return Object.keys(LEVELS).find((k) => LEVELS[k] === minLevel) || 'INFO';
}

/**
 * Routes every engine line into a host application's logger instead of stdout.
 *
 * This is how @fitfak/smtp gets database internals in the same stream, with the same
 * redaction and the same destination, as its own lines -- rather than a second logger
 * writing a second format to a second place.
 */
function setSink(hostLogger) { sink = hostLogger || null; return sink; }

function configure({ level, json, color, sink: hostLogger } = {}) {
  if (level) setLevel(level);
  if (json != null) jsonMode = !!json;
  if (color != null) colorEnabled = !!color;
  if (hostLogger !== undefined) setSink(hostLogger);
  if (jsonMode) colorEnabled = false;
  return { level: getLevel(), json: jsonMode, color: colorEnabled, sink: !!sink };
}

/** Shared no-op logger, so `logger || NULL_LOGGER` never needs a null check per call site. */
const NULL_LOGGER = {
  trace() {}, debug() {}, info() {}, warn() {}, error() {}, hex() {},
  enabled() { return false; },
  child() { return NULL_LOGGER; },
  timer() { return () => 0; },
};

module.exports = { mk, hexDump, setLevel, getLevel, setSink, configure, LEVELS, NULL_LOGGER };
