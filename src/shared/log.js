// Vigilant — tiny structured logger.
// One JSON line per call: { ts, level, msg, ...meta }. info/warn -> stdout, error -> stderr.
//
// Non-negotiable (docs/CONTRACT.md): NEVER print a secret. Any field named token,
// password, or authorization (at any depth) is replaced with "[redacted]" before output.

const SECRET_KEYS = new Set(["token", "password", "authorization"]);

// Recursively copy `value`, redacting any key that names a secret. Guards against
// cycles so a self-referential meta object can never crash the logger.
function redact(value, seen) {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[circular]";
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redact(item, seen));
  }

  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (SECRET_KEYS.has(key.toLowerCase())) {
      out[key] = "[redacted]";
    } else {
      out[key] = redact(val, seen);
    }
  }
  return out;
}

function emit(stream, level, msg, meta) {
  const line = { ts: new Date().toISOString(), level, msg: String(msg) };
  if (meta && typeof meta === "object") {
    Object.assign(line, redact(meta, new WeakSet()));
  }
  let serialised;
  try {
    serialised = JSON.stringify(line);
  } catch (e) {
    // Never let a logging failure take down a request path.
    serialised = JSON.stringify({ ts: line.ts, level, msg: line.msg, logError: e.message });
  }
  stream.write(serialised + "\n");
}

module.exports = {
  info(msg, meta) {
    emit(process.stdout, "info", msg, meta);
  },
  warn(msg, meta) {
    emit(process.stdout, "warn", msg, meta);
  },
  error(msg, meta) {
    emit(process.stderr, "error", msg, meta);
  },
};
