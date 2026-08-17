// The single dispatch path. Every capability on every device is reached through registry.invoke(),
// and both transports — the MCP server and the hub's HTTP API — are thin wrappers over exactly this
// call. That is deliberate and it is the one structural rule in Argus: the web UI cannot do anything
// an agent cannot do, and an agent cannot do anything the UI cannot, because there is no second way
// in. Permission checks, guards and redaction live here, so no transport can forget them.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { fail, ArgusError } from './errors.mjs'
import { redact } from './redact.mjs'
import { requireConfig } from './driver.mjs'

const BUILTIN_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'drivers')

async function importDriver(spec, root) {
  // "./local-driver.mjs" or an absolute path loads from disk; a bare name is a built-in, which may be
  // a single file or a directory when the vendor needs more than one protocol client
  const candidates = /^\.{1,2}[/\\]|^[/\\]|^[A-Za-z]:/.test(spec)
    ? [path.resolve(root, spec)]
    : [path.join(BUILTIN_DIR, `${spec}.mjs`), path.join(BUILTIN_DIR, spec, 'index.mjs')]

  const errors = []
  for (const file of candidates) {
    if (!fs.existsSync(file)) { errors.push(`${file} (not found)`); continue }
    try {
      const mod = await import(pathToFileURL(file).href)
      return mod.default ?? mod.driver
    } catch (e) { errors.push(`${file}: ${e.message}`) }
  }
  fail('DRIVER_UNKNOWN', `cannot load driver "${spec}"`, { driver: spec, tried: errors })
}

export class Registry {
  #devices = new Map()

  constructor(config) { this.config = config }

  static async load(config) {
    const reg = new Registry(config)
    for (const device of config.devices) {
      const driver = await importDriver(device.driver, config.paths.root)
      if (!driver) fail('DRIVER_UNKNOWN', `driver "${device.driver}" exports no default`, { device: device.id })
      requireConfig(device, driver.requires)

      const instance = driver.create(device, { policy: config.policy, site: config.site })
      const caps = new Map()
      for (const cap of instance.capabilities ?? []) {
        if (cap.kind === 'restart' && !config.policy.allowRestart) continue
        caps.set(cap.name, cap)
      }
      reg.#devices.set(device.id, { device, driver, instance, caps })
    }
    return reg
  }

  listDevices() {
    return [...this.#devices.values()].map(({ device, driver, caps }) => ({
      id: device.id,
      title: device.title ?? driver.title,
      role: device.role ?? null,
      driver: driver.type,
      vendor: driver.vendor,
      guard: device.guard,
      capabilities: [...caps.keys()],
    }))
  }

  listCapabilities({ kind } = {}) {
    const out = []
    for (const { device, caps } of this.#devices.values()) {
      for (const cap of caps.values()) {
        if (kind && cap.kind !== kind) continue
        out.push({ ref: `${device.id}.${cap.name}`, device: device.id, name: cap.name, title: cap.title, kind: cap.kind })
      }
    }
    return out
  }

  /** The capability definition itself — schema, kind, title — without running it. */
  capability(ref) {
    const { entry, cap } = this.#resolve(ref)
    return { ...cap, device: entry.device.id, ref }
  }

  /** "gateway.wifi.read" → the device id is everything before the first dot. */
  #resolve(ref) {
    const dot = String(ref).indexOf('.')
    if (dot < 1) fail('CAPABILITY_UNKNOWN', `"${ref}" is not a capability reference — expected "<device>.<capability>"`)
    const deviceId = ref.slice(0, dot)
    const capName = ref.slice(dot + 1)
    const entry = this.#devices.get(deviceId)
    if (!entry) fail('DEVICE_UNKNOWN', `no device "${deviceId}" in this config`, { known: [...this.#devices.keys()] })
    const cap = entry.caps.get(capName)
    if (!cap) fail('CAPABILITY_UNKNOWN', `device "${deviceId}" has no capability "${capName}"`, { known: [...entry.caps.keys()] })
    return { entry, cap }
  }

  /** A guarded band or SSID refuses before the driver is ever called. */
  #checkGuard(device, cap, args) {
    if (!cap.guardTarget) return
    const target = cap.guardTarget(args) ?? {}
    const band = target.band && device.guard.bands.includes(String(target.band))
    const ssid = target.ssid && device.guard.ssids.includes(String(target.ssid))
    if (band || ssid) {
      fail('GUARDED', `${device.id}: ${band ? `band "${target.band}"` : `SSID "${target.ssid}"`} is guarded in this config and will not be written`,
        { device: device.id, guard: device.guard })
    }
  }

  async invoke(ref, args = {}, { confirm = false } = {}) {
    const { entry, cap } = this.#resolve(ref)
    const { device, instance } = entry

    let input = args
    if (cap.input) {
      const parsed = cap.input.safeParse(args ?? {})
      if (!parsed.success) {
        fail('INPUT_INVALID', `bad arguments for ${ref}`, { issues: parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`) })
      }
      input = parsed.data
    }

    const mutating = cap.kind === 'write' || cap.kind === 'restart'
    if (mutating && this.config.policy.confirmWrites && confirm !== true) {
      fail('CONFIRM_REQUIRED', `${ref} changes device state — re-issue with confirm: true`, { ref, kind: cap.kind })
    }
    if (mutating) this.#checkGuard(device, cap, input)

    const started = Date.now()
    try {
      const result = await cap.run(input, { device, instance, registry: this, policy: this.config.policy })
      return { ref, kind: cap.kind, ms: Date.now() - started, result: redact(result) }
    } catch (e) {
      if (e instanceof ArgusError) throw e
      fail('DEVICE_REFUSED', `${ref} failed: ${e.message}`, { ref, device: device.id })
    }
  }

  /** Reachability + identity for every device, in parallel, never throwing. */
  async probeAll() {
    const entries = [...this.#devices.values()]
    return Promise.all(entries.map(async ({ device, driver, instance }) => {
      const started = Date.now()
      try {
        const r = await instance.probe()
        return { id: device.id, title: device.title ?? driver.title, driver: driver.type, ms: Date.now() - started, ...redact(r) }
      } catch (e) {
        return { id: device.id, title: device.title ?? driver.title, driver: driver.type, ms: Date.now() - started, ok: false, error: e.message }
      }
    }))
  }
}
