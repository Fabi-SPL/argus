// devolo dLAN powerline adapters with a WiFi radio. Firmware 6.x is OpenWrt underneath and exposes
// ubus JSON-RPC at /ubus, so this is the friendliest device in the house: real config objects, real
// session tokens, no form scraping.
//
// One rule is load-bearing and learned the hard way: radio state is read from `iwinfo`, never from
// the saved UCI config. Those two diverged once — UCI said the radio was up, the air said nothing was
// broadcasting — and the flat lost WiFi for an afternoon. `wireless.saved` exists to be compared
// against `radios.read`, not to be trusted on its own.

import { z } from 'zod'
import { defineDriver, defineCapability, requireConfig } from '../core/driver.mjs'
import { fingerprint } from '../core/redact.mjs'

const NULL_SID = '00000000000000000000000000000000'
const SETTLE_MS = 15_000        // how long the radios take to come back after a wireless commit
const GUEST = /gastzugang|guest/i
const NULL_BSSID = /^0{2}(:0{2}){5}$/i

/**
 * A radio that is still coming up answers `iwinfo` with an all-zero BSSID and reports `open`, which
 * is a lie that lasts a few seconds and would otherwise be returned as a security finding. Wait
 * until every named interface has a real BSSID before believing anything it says about encryption.
 */
async function settleRadios(u, tries = 5, waitMs = 5_000) {
  let radios = await liveRadios(u)
  for (let i = 0; i < tries; i++) {
    if (!radios.some((r) => r.ssid && NULL_BSSID.test(r.bssid ?? ''))) return radios
    await sleep(waitMs)
    radios = await liveRadios(u)
  }
  return radios
}

class Ubus {
  constructor({ host, password, username = 'root', timeout = 12_000 }) {
    Object.assign(this, { host, password, username, timeout })
    this.sid = null
  }

  async #rpc(params, id = 1) {
    const c = new AbortController()
    const t = setTimeout(() => c.abort(), this.timeout)
    try {
      const res = await fetch(`http://${this.host}/ubus`, {
        method: 'POST',
        signal: c.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'call', params }),
      })
      return await res.json()
    } finally { clearTimeout(t) }
  }

  /** ubus answers [code, payload]; 0 is success, 6 is permission denied. */
  static unwrap(r) {
    if (r?.error) return { ok: false, error: r.error.message ?? JSON.stringify(r.error) }
    const [code, payload] = r?.result ?? []
    return { ok: code === 0, code, data: payload }
  }

  async login() {
    const u = Ubus.unwrap(await this.#rpc([NULL_SID, 'session', 'login', { username: this.username, password: this.password }]))
    if (!u.ok) return { ok: false, code: u.code, error: u.error }
    this.sid = u.data?.ubus_rpc_session
    return { ok: Boolean(this.sid), expires: u.data?.expires }
  }

  async call(object, method, args = {}) {
    if (!this.sid) {
      const l = await this.login()
      if (!l.ok) throw new Error(`login refused (${l.code ?? l.error})`)
    }
    return Ubus.unwrap(await this.#rpc([this.sid, object, method, args], 2))
  }

  uciGet(config, section) { return this.call('uci', 'get', section ? { config, section } : { config }) }
  uciSet(config, section, values) { return this.call('uci', 'set', { config, section, values }) }
  uciCommit(config) { return this.call('uci', 'commit', { config }) }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * iwinfo reports encryption as a structure, not a name, and the naive reading of it is wrong in a
 * way that matters: a healthy WPA2-PSK radio reports `authentication: ["none"]`, because that field
 * lists 802.11 auth suites, not whether the network has a key. Reading that string as "open" would
 * have the posture panel screaming about an encrypted network. `enabled` is the field that answers
 * the question.
 */
function describeEncryption(e) {
  if (!e) return null
  if (!e.enabled) return 'open'
  const wpa = (e.wpa ?? []).map((v) => (v === 1 ? 'WPA' : `WPA${v}`)).join('/')
  const auth = (e.authentication ?? []).filter((a) => a && a !== 'none').join('+')
  const ciphers = (e.ciphers ?? []).join('+').toUpperCase()
  return `${wpa || 'WEP'}${auth ? `-${auth.toUpperCase()}` : ''}${ciphers ? ` (${ciphers})` : ''}`
}

/** The only trustworthy view of what is on air right now. */
async function liveRadios(u) {
  const devices = await u.call('iwinfo', 'devices').catch(() => ({ ok: false }))
  const names = devices.ok ? (devices.data?.devices ?? []) : ['ath0', 'ath1']
  const out = []
  for (const dev of names) {
    const info = await u.call('iwinfo', 'info', { device: dev }).catch(() => ({ ok: false }))
    if (!info.ok) continue
    const clients = await u.call('iwinfo', 'assoclist', { device: dev }).catch(() => ({ ok: false }))
    out.push({
      interface: dev,
      ssid: info.data?.ssid,
      bssid: info.data?.bssid,
      mode: info.data?.mode,
      channel: info.data?.channel,
      encryption: describeEncryption(info.data?.encryption),
      txpower: info.data?.txpower,
      clients: clients.ok ? (clients.data?.results ?? []).length : null,
    })
  }
  return out
}

async function wirelessSections(u) {
  const r = await u.uciGet('wireless')
  if (!r.ok) throw new Error(`uci get wireless failed (${r.code})`)
  return Object.entries(r.data?.values ?? {})
}

const isGuest = (s) => s.dvl_guest === '1' || GUEST.test(s.ssid ?? '')

export default defineDriver({
  type: 'devolo-dlan',
  title: 'devolo dLAN (WiFi powerline adapter)',
  vendor: 'devolo',
  requires: ['host', 'password'],
  optional: ['username'],

  create(device) {
    const u = new Ubus({ host: device.host, password: device.password, username: device.username ?? 'root' })

    return {
      async probe() {
        const l = await u.login()
        if (!l.ok) return { ok: false, error: `login refused (${l.code ?? l.error})` }
        const board = await u.call('system', 'board').catch(() => ({ ok: false }))
        return {
          ok: true,
          identity: {
            model: board.data?.model ?? null,
            firmware: board.data?.release?.description ?? null,
            kernel: board.data?.kernel ?? null,
          },
          radios: await liveRadios(u),
        }
      },

      capabilities: [
        defineCapability({
          name: 'radios.read',
          title: 'Live radio state',
          kind: 'read',
          input: z.object({}),
          run: () => liveRadios(u),
        }),

        defineCapability({
          name: 'air.scan',
          title: 'Scan the air',
          kind: 'diagnose',
          input: z.object({
            interfaces: z.array(z.string()).default(['ath0', 'ath1']).describe('Radios to survey from.'),
          }),
          async run({ interfaces }) {
            const out = {}
            for (const dev of interfaces) {
              const r = await u.call('iwinfo', 'scan', { device: dev }).catch((e) => ({ ok: false, error: e.message }))
              out[dev] = r.ok
                ? (r.data?.results ?? [])
                  .sort((a, b) => (b.signal ?? -99) - (a.signal ?? -99))
                  .map((n) => ({ ssid: n.ssid || '(hidden)', channel: n.channel, signal: n.signal, bssid: n.bssid }))
                : { error: r.code ?? r.error }
            }
            return out
          },
        }),

        defineCapability({
          name: 'clients.list',
          title: 'Associated clients',
          kind: 'read',
          input: z.object({}),
          async run() {
            const devices = await u.call('iwinfo', 'devices').catch(() => ({ ok: false }))
            const names = devices.ok ? (devices.data?.devices ?? []) : ['ath0', 'ath1']
            const out = []
            for (const dev of names) {
              const r = await u.call('iwinfo', 'assoclist', { device: dev }).catch(() => ({ ok: false }))
              for (const c of r.data?.results ?? []) {
                out.push({ interface: dev, mac: c.mac, signal: c.signal, rxRate: c.rx?.rate, txRate: c.tx?.rate })
              }
            }
            return out
          },
        }),

        defineCapability({
          name: 'wireless.saved',
          title: 'Saved wireless config',
          kind: 'read',
          input: z.object({}),
          async run() {
            const sections = await wirelessSections(u)
            return Object.fromEntries(sections)   // secrets are stripped by the registry on the way out
          },
        }),

        defineCapability({
          name: 'ssid.set',
          title: 'Rename every non-guest network',
          kind: 'write',
          input: z.object({
            ssid: z.string().min(1).max(32).describe('New network name.'),
            dryRun: z.boolean().default(true).describe('Report the plan without writing. Default true.'),
          }),
          guardTarget: ({ ssid }) => ({ ssid }),
          async run({ ssid, dryRun }) {
            const before = await liveRadios(u)
            const plan = []
            for (const [name, sec] of await wirelessSections(u)) {
              // a saved disabled=1 on the radio is what took the flat offline once — force it back
              if (sec['.type'] === 'wifi-device') {
                if (sec.disabled !== '0') plan.push([name, { disabled: '0' }, `radio ${sec.hwmode ?? ''} → keep ON`])
                continue
              }
              if (sec['.type'] !== 'wifi-iface' || isGuest(sec)) continue
              if (sec.ssid !== ssid) plan.push([name, { ssid, disabled: '0' }, `"${sec.ssid}" → "${ssid}"`])
            }

            if (dryRun) return { mode: 'dry run', before, plan: plan.map(([n, , label]) => `${n}  ${label}`) }

            for (const [name, values] of plan) {
              const r = await u.uciSet('wireless', name, values)
              if (!r.ok) throw new Error(`uci set ${name} failed (${r.code}) — nothing committed`)
            }
            const c = await u.uciCommit('wireless')
            if (!c.ok) throw new Error(`commit failed (${c.code})`)

            const after = await settleRadios(u)
            const up = after.filter((r) => r.ssid === ssid).length
            return {
              mode: 'applied', before, after, broadcasting: up,
              ...(up ? {} : { warning: 'nothing is broadcasting — bring the radios back with radios.enable' }),
            }
          },
        }),

        // The new passphrase is deliberately NOT an argument. It is read from `wifi_key` in the
        // device config, which resolves from .env — so the value never appears in a tool call, an
        // MCP transcript, a hub request body or a shell history. The caller chooses *whether* to
        // rotate; the operator chooses *to what*, out of band. Every other design here leaks.
        defineCapability({
          name: 'key.set',
          title: 'Rotate the passphrase on every non-guest network',
          kind: 'write',
          input: z.object({
            dryRun: z.boolean().default(true).describe('Report the plan without writing. Default true.'),
          }),
          async run({ dryRun }) {
            requireConfig(device, ['wifi_key'])
            const key = device.wifi_key
            if (key.length < 8 || key.length > 63) {
              throw new Error(`wifi_key is ${key.length} characters — WPA2 accepts 8 to 63`)
            }
            const { fp } = fingerprint(key)

            const plan = []
            const notes = []
            for (const [name, sec] of await wirelessSections(u)) {
              if (sec['.type'] !== 'wifi-iface' || isGuest(sec)) continue
              if (!/^psk/.test(sec.encryption ?? '')) {
                notes.push(`${name} is "${sec.encryption ?? 'unset'}", not WPA-PSK — a key there changes nothing`)
                continue
              }
              if (sec.key === key) { notes.push(`${name} already carries this passphrase`); continue }
              plan.push([name, { key }, `"${sec.ssid}" → new passphrase (${key.length} chars, ${fp})`])
            }

            if (dryRun) {
              return { mode: 'dry run', newKey: { length: key.length, fingerprint: fp }, notes,
                plan: plan.map(([n, , label]) => `${n}  ${label}`) }
            }

            for (const [name, values] of plan) {
              const r = await u.uciSet('wireless', name, values)
              if (!r.ok) throw new Error(`uci set ${name} failed (${r.code}) — nothing committed`)
            }
            const c = await u.uciCommit('wireless')
            if (!c.ok) throw new Error(`commit failed (${c.code})`)

            const after = await settleRadios(u)
            return {
              mode: 'applied', changed: plan.length, notes,
              newKey: { length: key.length, fingerprint: fp },
              broadcasting: after.filter((r) => r.ssid).length,
              radios: after,
              reminder: 'every device on these networks must rejoin with the new passphrase',
            }
          },
        }),

        defineCapability({
          name: 'guest.set',
          title: 'Guest network on/off',
          kind: 'write',
          input: z.object({
            enabled: z.boolean(),
            dryRun: z.boolean().default(true),
          }),
          async run({ enabled, dryRun }) {
            const want = enabled ? '0' : '1'
            const plan = (await wirelessSections(u))
              .filter(([, s]) => s['.type'] === 'wifi-iface' && isGuest(s))
              .filter(([, s]) => (s.disabled ?? '0') !== want)
              .map(([name, s]) => [name, `guest "${s.ssid}" → ${enabled ? 'ON' : 'OFF'}`])

            if (dryRun) return { mode: 'dry run', plan: plan.map(([n, l]) => `${n}  ${l}`) }

            for (const [name] of plan) {
              const r = await u.uciSet('wireless', name, { disabled: want })
              if (!r.ok) throw new Error(`uci set ${name} failed (${r.code}) — nothing committed`)
            }
            const c = await u.uciCommit('wireless')
            if (!c.ok) throw new Error(`commit failed (${c.code})`)
            await sleep(SETTLE_MS)
            return { mode: 'applied', changed: plan.length, radios: await liveRadios(u) }
          },
        }),

        defineCapability({
          name: 'radios.enable',
          title: 'Force every radio back on',
          kind: 'write',
          input: z.object({ dryRun: z.boolean().default(true) }),
          async run({ dryRun }) {
            const plan = (await wirelessSections(u))
              .filter(([, s]) => (s['.type'] === 'wifi-device' || s['.type'] === 'wifi-iface') && !isGuest(s))
              .filter(([, s]) => (s.disabled ?? '0') !== '0')
              .map(([name, s]) => [name, `${s['.type']} ${s.ssid ?? s.hwmode ?? ''} → ON`])

            if (dryRun) return { mode: 'dry run', plan: plan.map(([n, l]) => `${n}  ${l}`) }
            for (const [name] of plan) await u.uciSet('wireless', name, { disabled: '0' })
            const c = await u.uciCommit('wireless')
            if (!c.ok) throw new Error(`commit failed (${c.code})`)
            await sleep(SETTLE_MS)
            return { mode: 'applied', changed: plan.length, radios: await liveRadios(u) }
          },
        }),
      ],
    }
  },
})
