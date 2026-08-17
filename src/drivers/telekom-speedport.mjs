// Telekom Speedport (Sercomm firmware, W724V era). Everything is a form-encoded POST or GET against
// /data/<Page>.json, answered with a flat [{varid,varvalue,vartype},…] list that has to be folded
// back into an object. Three things about this box are non-obvious and all three are load-bearing:
//
//   • it 302s unless the request carries `Host: speedport.ip`, whatever address you dialled
//   • it emits a malformed header on POST /data/*.json, which Node's strict parser refuses outright,
//     so the socket is opened with insecureHTTPParser
//   • `use_wlan: 0` does NOT mean the radio is off. If hsfon_status is 1 the Telekom WLAN TO GO
//     hotspot keeps the radio powered and beaconing under its own SSID. Read the air, not the flag —
//     status reports both and says so.
//
// Page names vary by firmware, so this driver assumes only Login and Status. `pages.discover` probes
// a candidate list and reports which ones this box actually answers, and `page.read` fetches any of
// them; that is how the firewall and NAT pages get found rather than guessed.

import http from 'node:http'
import { z } from 'zod'
import { defineDriver, defineCapability } from '../core/driver.mjs'

const HOST_HEADER = 'speedport.ip'
const CSRF = 'sercomm_csrf_token'

const CANDIDATE_PAGES = [
  'Status', 'Overview', 'Internet', 'InternetConnection', 'LAN', 'LANClients', 'DeviceList',
  'WLANBasic', 'WLANEncryption', 'WLANGuest', 'WLANTimer', 'WLANStatus',
  'Firewall', 'NAT', 'PortForward', 'PortForwarding', 'DynDNS', 'UPnP',
  'Phone', 'Telephony', 'System', 'SystemInfo', 'Log', 'Update',
]

/** The JSON endpoints answer with a flat varid/varvalue list; fold it into a plain object. */
export function toObject(payload) {
  const out = {}
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk)
    if (!node || typeof node !== 'object') return
    if (node.varid !== undefined) {
      out[node.varid] = Array.isArray(node.varvalue) ? node.varvalue.map(toObject) : node.varvalue
      return
    }
    Object.values(node).forEach(walk)
  }
  walk(payload)
  return out
}

class Sercomm {
  constructor({ host, password }) {
    this.host = host
    this.password = password
    this.cookies = new Map()
    this.authed = false
  }

  #request(method, pathname, body) {
    const payload = body == null ? null : Buffer.from(body, 'utf8')
    return new Promise((resolve) => {
      const headers = {
        Host: HOST_HEADER,
        'User-Agent': 'Mozilla/5.0',
        Accept: 'application/json, text/javascript, */*',
        Connection: 'close',
        ...(this.cookies.size ? { Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ') } : {}),
        ...(payload ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': payload.length } : {}),
      }
      const req = http.request(
        { host: this.host, port: 80, path: pathname, method, headers, timeout: 20_000, insecureHTTPParser: true },
        (res) => {
          for (const c of res.headers['set-cookie'] ?? []) {
            const [k, v] = c.split(';')[0].split('=')
            if (k) this.cookies.set(k.trim(), v ?? '')
          }
          let out = ''
          res.setEncoding('utf8')
          res.on('data', (c) => { out += c })
          res.on('end', () => resolve({ status: res.statusCode, body: out, location: res.headers.location }))
        })
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '(timeout)' }) })
      req.on('error', (e) => resolve({ status: 0, body: e.message }))
      req.end(payload ?? undefined)
    })
  }

  #parse(res) {
    const text = res.body.trim().replace(/,(\s*[}\]])/g, '$1')   // firmware emits trailing commas
    try { return toObject(JSON.parse(text)) } catch { return null }
  }

  async post(page, fields) {
    const body = new URLSearchParams({ ...fields, csrf_token: CSRF }).toString()
    const res = await this.#request('POST', `/data/${page}.json?lang=de`, body)
    return { status: res.status, data: this.#parse(res), raw: res.body }
  }

  async load(page) {
    const q = `_time=${Date.now()}&_rand=${Math.floor(Math.random() * 1001)}&csrf_token=${CSRF}&lang=de`
    const res = await this.#request('GET', `/data/${page}.json?${q}`)
    return { status: res.status, data: this.#parse(res), raw: res.body, location: res.location }
  }

  async login() {
    if (this.authed) return { ok: true, cached: true }
    await this.#request('GET', '/html/login/index.html')
    const r = await this.post('Login', { password: this.password, showpw: '0' })
    const state = r.data ?? {}
    this.authed = state.login === 'success'
    return { ok: this.authed, login: state.login, locked: state.login_locked, other: state.login_other, status: r.status }
  }

  logout() { this.authed = false; return this.post('Login', { logout: 'byby' }) }
}

async function session(s) {
  const l = await s.login()
  if (!l.ok) throw new Error(`login refused (${l.login ?? l.status})`)
  return s
}

export default defineDriver({
  type: 'telekom-speedport',
  title: 'Telekom Speedport (Sercomm firmware)',
  vendor: 'Telekom',
  requires: ['host', 'password'],

  create(device) {
    const s = new Sercomm({ host: device.host, password: device.password })

    const status = async () => {
      const d = (await (await session(s)).load('Status')).data ?? {}
      const hotspot = d.hsfon_status === '1'
      return {
        model: d.device_name,
        type: d.device_type,
        firmware: d.firmware_version,
        internet: d.onlinestatus,
        dsl: { status: d.dsl_status, downstreamKbit: d.dsl_downstream, upstreamKbit: d.dsl_upstream },
        wifi24: { ssid: d.wlan_ssid, enabled: d.use_wlan === '1' },
        wifi5: { ssid: d.wlan_5ghz_ssid, enabled: d.use_wlan_5ghz === '1' },
        hotspot,
        radioLikelyLive: hotspot || d.use_wlan === '1' || d.use_wlan_5ghz === '1',
        ...(hotspot && d.use_wlan !== '1'
          ? { note: 'WLAN TO GO is on, so the 2.4 GHz radio is beaconing even though use_wlan reads 0. Confirm against an air scan.' }
          : {}),
        time: d.datetime,
      }
    }

    return {
      async probe() {
        const l = await s.login()
        if (!l.ok) return { ok: false, error: `login refused (${l.login ?? l.status})` }
        const d = (await s.load('Status')).data ?? {}
        return { ok: true, identity: { model: d.device_name, firmware: d.firmware_version }, internet: d.onlinestatus }
      },

      capabilities: [
        defineCapability({
          name: 'status',
          title: 'Gateway status',
          kind: 'read',
          input: z.object({}),
          run: status,
        }),

        defineCapability({
          name: 'page.read',
          title: 'Read one /data page',
          kind: 'read',
          input: z.object({
            page: z.string().regex(/^[A-Za-z0-9_]+$/).describe('Page name without the .json, e.g. Status or Firewall.'),
          }),
          async run({ page }) {
            const r = await (await session(s)).load(page)
            if (!r.data) return { page, status: r.status, ok: false, hint: 'no JSON — the page may not exist on this firmware, or may be gated behind its owning HTML page' }
            return { page, status: r.status, ok: true, data: r.data }
          },
        }),

        defineCapability({
          name: 'pages.discover',
          title: 'Find which /data pages this firmware answers',
          kind: 'diagnose',
          input: z.object({
            pages: z.array(z.string()).default(CANDIDATE_PAGES).describe('Candidate page names to probe.'),
          }),
          async run({ pages }) {
            await session(s)
            const found = []
            const missing = []
            for (const page of pages) {
              const r = await s.load(page)
              if (r.data && Object.keys(r.data).length) found.push({ page, keys: Object.keys(r.data).length })
              else missing.push(page)
            }
            return { found, missing }
          },
        }),

        defineCapability({
          name: 'clients.list',
          title: 'Devices seen by the gateway',
          kind: 'read',
          input: z.object({}),
          async run() {
            await session(s)
            for (const page of ['DeviceList', 'LANClients', 'Overview', 'LAN']) {
              const r = await s.load(page)
              const rows = Object.values(r.data ?? {}).find((v) => Array.isArray(v) && v.some((x) => x && (x.mac ?? x.macaddress ?? x.ipaddress)))
              if (rows) return { page, clients: rows }
            }
            return { clients: [], hint: 'no client list page answered — run pages.discover to see what this firmware exposes' }
          },
        }),
      ],
    }
  },
})
