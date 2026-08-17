// Argus is expected to be run by an agent that pipes its output straight into a transcript, so no
// secret may ever leave the core. Values are stripped by key name on the way out, and where a caller
// genuinely needs to compare two passphrases without seeing either — "is the 5 GHz key the same as
// the 2.4 GHz key?" — fingerprint() answers that with a sha256 head and a length instead.

import { createHash } from 'node:crypto'

const SECRET_KEY = /(^|[._-])(key|keys|password|passwd|pass|psk|passphrase|secret|token|apikey|auth_secret|credential|guest_key)s?\d*$/i

export const isSecretKey = (name) => SECRET_KEY.test(String(name))

/** A stable, non-reversible handle for a secret: safe to print, safe to compare. */
export function fingerprint(value) {
  if (value === undefined || value === null || value === '') return null
  const s = String(value)
  return { fp: createHash('sha256').update(s).digest('hex').slice(0, 8), length: s.length }
}

/** Deep copy with every secret-named value replaced by «redacted». Cycles are tolerated. */
export function redact(value, seen = new WeakSet()) {
  if (Array.isArray(value)) {
    if (seen.has(value)) return '«cycle»'
    seen.add(value)
    return value.map((v) => redact(v, seen))
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) return '«cycle»'
    seen.add(value)
    return Object.fromEntries(Object.entries(value).map(([k, v]) =>
      [k, isSecretKey(k) && v ? '«redacted»' : redact(v, seen)]))
  }
  return value
}

/**
 * Same as redact(), but secret-named values become their fingerprint rather than vanishing. Use for
 * diagnostics where the question is whether two devices agree, not what the value is.
 */
export function redactToFingerprints(value, seen = new WeakSet()) {
  if (Array.isArray(value)) {
    if (seen.has(value)) return '«cycle»'
    seen.add(value)
    return value.map((v) => redactToFingerprints(v, seen))
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) return '«cycle»'
    seen.add(value)
    return Object.fromEntries(Object.entries(value).map(([k, v]) =>
      [k, isSecretKey(k) && v ? fingerprint(v) : redactToFingerprints(v, seen)]))
  }
  return value
}
