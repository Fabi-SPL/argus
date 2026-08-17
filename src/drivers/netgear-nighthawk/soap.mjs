// NETGEAR's SOAP surface, at https://<host>/soap/server_sa/ behind a self-signed cert.
//
// The one thing to know: firmware in the RAX era answers 401 to a Content-Type of text/xml and
// accepts multipart/form-data instead, for a body that is neither. That is not a typo below.

import https from 'node:https'

const SESSION_ID = 'A7D88AE69687E58D9A00'
const PATH = '/soap/server_sa/'

export const SERVICE = {
  deviceInfo: 'urn:NETGEAR-ROUTER:service:DeviceInfo:1',
  deviceConfig: 'urn:NETGEAR-ROUTER:service:DeviceConfig:1',
  wlan: 'urn:NETGEAR-ROUTER:service:WLANConfiguration:1',
  lan: 'urn:NETGEAR-ROUTER:service:LANConfigSecurity:1',
  wan: 'urn:NETGEAR-ROUTER:service:WANIPConnection:1',
  parental: 'urn:NETGEAR-ROUTER:service:ParentalControl:1',
  advanced: 'urn:NETGEAR-ROUTER:service:AdvancedQoS:1',
}

const envelope = (service, method, inner = '') => `<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAPSDK1="http://www.w3.org/2001/XMLSchema"
 xmlns:SOAPSDK2="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:SOAPSDK3="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header><SessionID>${SESSION_ID}</SessionID></SOAP-ENV:Header>
<SOAP-ENV:Body><M1:${method} xmlns:M1="${service}">${inner}</M1:${method}></SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

function post(host, action, body, cookie) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(body, 'utf8')
    const req = https.request({
      host, port: 443, path: PATH, method: 'POST',
      rejectUnauthorized: false,
      headers: {
        SOAPAction: action,
        'Cache-Control': 'no-cache',
        'User-Agent': 'pynetgear',
        'Content-Type': 'multipart/form-data',   // text/xml is answered with 401 by this firmware
        'Content-Length': data.length,
        ...(cookie ? { Cookie: cookie } : {}),
      },
      timeout: 15_000,
    }, (res) => {
      let out = ''
      res.setEncoding('utf8')
      res.on('data', (c) => { out += c })
      res.on('end', () => resolve({ status: res.statusCode, body: out, headers: res.headers }))
    })
    req.on('timeout', () => req.destroy(new Error('timed out after 15s')))
    req.on('error', reject)
    req.end(data)
  })
}

export const tag = (xml, name) => xml.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, 'i'))?.[1]?.trim() ?? null
export const code = (xml) => tag(xml, 'ResponseCode')
export const ok = (xml) => ['000', '0'].includes(code(xml) ?? '')

export class NetgearSoap {
  constructor({ host, user = 'admin', password }) {
    Object.assign(this, { host, user, password })
    this.cookie = null
    this.authed = false
  }

  async call(service, method, inner = '') {
    const svc = SERVICE[service] ?? service
    const res = await post(this.host, `${svc}#${method}`, envelope(svc, method, inner), this.cookie)
    if (res.headers['set-cookie']) this.cookie = res.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ')
    return res
  }

  /** SOAPLogin on newer firmware, Authenticate on older. Reports which one took. */
  async login() {
    if (this.authed) return { ok: true, cached: true }
    const v2 = await this.call('deviceConfig', 'SOAPLogin', `<Username>${this.user}</Username><Password>${this.password}</Password>`)
    if (ok(v2.body)) { this.authed = true; return { ok: true, method: 'SOAPLogin' } }

    const v1 = await this.call('parental', 'Authenticate', `<NewUsername>${this.user}</NewUsername><NewPassword>${this.password}</NewPassword>`)
    if (ok(v1.body)) { this.authed = true; return { ok: true, method: 'Authenticate' } }

    return { ok: false, method: null, code: code(v2.body) ?? code(v1.body), status: v2.status }
  }

  async deviceInfo() {
    const r = await this.call('deviceInfo', 'GetInfo')
    return {
      ok: ok(r.body),
      model: tag(r.body, 'ModelName'),
      firmware: tag(r.body, 'Firmwareversion'),
      serial: tag(r.body, 'SerialNumber'),
      deviceMode: tag(r.body, 'DeviceMode'),   // 0 router · 1 access point · 2 bridge · 3 repeater
    }
  }

  /** Per-band wireless state. The RAX line is tri-band: 2.4, 5G-1, 5G-2. */
  async bands() {
    const list = [['2.4', 'GetInfo'], ['5g1', 'Get5GInfo'], ['5g2', 'Get5G1Info']]
    const out = []
    for (const [band, method] of list) {
      const r = await this.call('wlan', method)
      out.push({
        band,
        ok: ok(r.body), code: code(r.body),
        enabled: tag(r.body, 'NewEnable'),
        status: tag(r.body, 'NewStatus'),
        ssid: tag(r.body, 'NewSSID') ?? tag(r.body, 'SSID'),
        broadcast: tag(r.body, 'NewSSIDBroadcast'),
        channel: tag(r.body, 'NewChannel') ?? tag(r.body, 'Channel'),
        mode: tag(r.body, 'NewWirelessMode'),
        security: tag(r.body, 'NewBasicEncryptionModes') ?? tag(r.body, 'BasicEncryptionModes'),
        region: tag(r.body, 'NewRegion'),
      })
    }
    return out
  }

  /** Passphrases per band. Never returned raw to a caller — the driver fingerprints them. */
  async securityKeys() {
    const list = [['2.4', 'GetWPASecurityKeys'], ['5g1', 'Get5GWPASecurityKeys'], ['5g2', 'Get5G1WPASecurityKeys']]
    const out = []
    for (const [band, method] of list) {
      const r = await this.call('wlan', method)
      out.push({ band, ok: ok(r.body), code: code(r.body), passphrase: tag(r.body, 'NewWPAPassphrase') ?? tag(r.body, 'NewPassphrase') })
    }
    return out
  }

  async attachedDevices() {
    const r = await this.call('deviceInfo', 'GetAttachDevice')
    const raw = tag(r.body, 'NewAttachDevice') ?? ''
    // "count@id;ip;name;mac;type;link@id;ip;…" — an @-delimited list of ;-delimited records
    const [, ...records] = raw.split('@')
    return {
      ok: ok(r.body),
      code: code(r.body),
      devices: records.filter(Boolean).map((rec) => {
        const [id, ip, name, mac, type, link] = rec.split(';')
        return { id, ip, name, mac, type, link }
      }),
    }
  }

  setRadio(band, on) {
    const method = { '2.4': 'SetEnable', '5g1': 'Set5GEnable', '5g2': 'Set5G1Enable' }[band]
    if (!method) throw new Error(`unknown band "${band}"`)
    return this.call('wlan', method, `<NewEnable>${on ? '1' : '0'}</NewEnable>`)
      .then((r) => ({ ok: ok(r.body), code: code(r.body) }))
  }

  setSsidAndKey(band, ssid, passphrase) {
    const method = {
      '2.4': 'SetWLANWPAPSKByPassphrase',
      '5g1': 'Set5GWLANWPAPSKByPassphrase',
      '5g2': 'Set5G1WLANWPAPSKByPassphrase',
    }[band]
    if (!method) throw new Error(`unknown band "${band}"`)
    return this.call('wlan', method, `<NewSSID>${ssid}</NewSSID><NewWPAPassphrase>${passphrase}</NewWPAPassphrase>`)
      .then((r) => ({ ok: ok(r.body), code: code(r.body), status: r.status }))
  }

  /** Opens a config session — firmware rejects most writes with 402 until this is called. */
  configStart() {
    return this.call('deviceConfig', 'ConfigurationStarted', `<NewSessionID>${SESSION_ID}</NewSessionID>`)
      .then((r) => ({ ok: ok(r.body), code: code(r.body) }))
  }

  configFinish() {
    return this.call('deviceConfig', 'ConfigurationFinished', '<NewStatus>ChangesApplied</NewStatus>')
      .then((r) => ({ ok: ok(r.body), code: code(r.body) }))
  }

  /** Fires an action verbatim. This is how you find out what a given firmware actually implements. */
  async probe(service, method, inner = '') {
    const r = await this.call(service, method, inner)
    return { ok: ok(r.body), code: code(r.body), status: r.status, body: r.body.slice(0, 2000) }
  }
}
