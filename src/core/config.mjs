// Everything site-specific — addresses, credentials, network names, tailnet identifiers — lives in
// argus.config.json, and anything sensitive in there is written as a ${ENV_VAR} reference resolved
// from .env at load time. The source tree therefore contains no address and no secret, and a config
// file can be handed to someone else without its .env.
//
// A device entry may also carry a `guard`, which is the mechanism behind the one rule every home
// network turns out to need: some radio must never be touched by automation. Here that is a headset's
// dedicated band, but the shape is general — a guarded band or SSID makes every write capability
// refuse before it reaches the driver.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { ArgusError, fail } from './errors.mjs'

const ENV_REF = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/
const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/

/** Minimal .env reader — no dependency, and it never returns the values it read to a caller. */
export function readEnvFile(file) {
  const env = {}
  if (!fs.existsSync(file)) return env
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith('#')) continue
    const m = line.match(ENV_LINE)
    if (!m) continue
    let v = m[2].trim()
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1)
    env[m[1]] = v
  }
  return env
}

/** Replaces every "${VAR}" leaf with its environment value. Missing vars are reported, not guessed. */
function resolve(node, env, missing, trail = []) {
  if (typeof node === 'string') {
    const m = node.match(ENV_REF)
    if (!m) return node
    const v = env[m[1]]
    if (v === undefined || v === '') { missing.push({ var: m[1], at: trail.join('.') }); return null }
    return v
  }
  if (Array.isArray(node)) return node.map((v, i) => resolve(v, env, missing, [...trail, i]))
  if (node && typeof node === 'object') {
    return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, resolve(v, env, missing, [...trail, k])]))
  }
  return node
}

const DEFAULT_POLICY = {
  confirmWrites: true,     // write capabilities need an explicit confirm:true from the caller
  allowRestart: false,     // reboot/restart capabilities are hidden unless turned on
  hubBind: '127.0.0.1',
  hubPort: 4380,
}

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

/**
 * An MCP client launches the server with an arbitrary working directory, so cwd alone is not a
 * reliable place to look. Prefer an explicit path, then cwd if it actually holds a config, then the
 * package root — which is where a cloned checkout keeps its own.
 */
function locate(name, explicit, envVar) {
  if (explicit) return explicit
  if (process.env[envVar]) return process.env[envVar]
  const inCwd = path.join(process.cwd(), name)
  return fs.existsSync(inCwd) ? inCwd : path.join(PACKAGE_ROOT, name)
}

export function loadConfig({ root, configFile, envFile } = {}) {
  const cfgPath = root ? path.join(root, 'argus.config.json') : locate('argus.config.json', configFile, 'ARGUS_CONFIG')
  const envPath = root ? path.join(root, '.env') : locate('.env', envFile, 'ARGUS_ENV')
  const dir = path.dirname(cfgPath)   // relative driver paths resolve against the config, not cwd

  if (!fs.existsSync(cfgPath)) {
    fail('CONFIG_INVALID', `no config at ${cfgPath} — copy argus.config.example.json and fill it in`, { path: cfgPath })
  }

  let raw
  try { raw = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) }
  catch (e) { fail('CONFIG_INVALID', `${path.basename(cfgPath)} is not valid JSON: ${e.message}`, { path: cfgPath }) }

  const env = { ...readEnvFile(envPath), ...process.env }
  const missing = []
  const cfg = resolve(raw, env, missing)

  if (missing.length) {
    const names = [...new Set(missing.map((m) => m.var))]
    fail('CONFIG_INVALID', `unset environment variables referenced by the config: ${names.join(', ')}`,
      { missing: names, envPath })
  }

  if (!Array.isArray(cfg.devices) || cfg.devices.length === 0) {
    fail('CONFIG_INVALID', 'config has no devices', { path: cfgPath })
  }

  const seen = new Set()
  for (const d of cfg.devices) {
    if (!d.id) fail('CONFIG_INVALID', 'every device needs an id')
    if (!d.driver) fail('CONFIG_INVALID', `device "${d.id}" has no driver`)
    if (seen.has(d.id)) fail('CONFIG_INVALID', `duplicate device id "${d.id}"`)
    seen.add(d.id)
    d.guard = { bands: [], ssids: [], ...(d.guard ?? {}) }
  }

  return {
    site: cfg.site ?? { name: 'home' },
    devices: cfg.devices,
    policy: { ...DEFAULT_POLICY, ...(cfg.policy ?? {}) },
    paths: { config: cfgPath, env: envPath, root: dir },
  }
}

export { ArgusError }
