// The NETGEAR web UI, used where SOAP refuses. Its login page hands over the whole mechanism in
// plaintext:
//
//   var ts = "34399619";
//   $.ajax({ url: "/apply.cgi?" + (htm||'') + " timestamp=" + ts, type: "POST",
//            data: {submit_flag:"admin_login", username: …, password: $.base64.encode(…)} })
//   if (result == 5) top.location.href = "unauth.cgi"
//
// which is also why a bare `5` comes back from apply.cgi sometimes: that is the not-authenticated
// sentinel, not a truncated body.
//
// Two things matter for every request after login — the session cookie, and a `timestamp` token
// minted fresh into whichever page owns the form being submitted. Posting a form with another page's
// timestamp fails silently, so every write re-reads its own page first.

import https from 'node:https'

const ENC = 'application/x-www-form-urlencoded; charset=UTF-8'

// /jquery.base64.min.js does NOT ship stock base64. Its encoder ends:
//
//   return b[Math.ceil(62*Math.random())] + a + "====".slice(a.length%4||4)
//
// — one random character from the alphabet glued to the front, which the firmware strips again.
// Send stock base64 and the login is rejected; enough rejections and the router answers every path
// with unauth.cgi for a minute. A whole afternoon's lockout was this single character.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function netgearEncode(plain) {
  return ALPHABET[Math.ceil(Math.random() * 62)] + Buffer.from(plain, 'utf8').toString('base64')
}

export class NetgearWeb {
  constructor({ host, user = 'admin', password }) {
    Object.assign(this, { host, user, password })
    this.cookie = null
    this.authed = false
  }

  #request(method, pathname, body = null, extraHeaders = {}) {
    return new Promise((resolve) => {
      const data = body == null ? null : Buffer.from(body, 'utf8')
      const req = https.request({
        host: this.host, port: 443, path: pathname, method,
        rejectUnauthorized: false, timeout: 20_000,
        headers: {
          'User-Agent': 'Mozilla/5.0',
          Referer: `https://${this.host}/`,
          ...(data ? { 'Content-Type': ENC, 'Content-Length': data.length } : {}),
          ...(this.cookie ? { Cookie: this.cookie } : {}),
          ...extraHeaders,
        },
      }, (res) => {
        if (res.headers['set-cookie']) this.cookie = res.headers['set-cookie'].map((c) => c.split(';')[0]).join('; ')
        let out = ''
        res.setEncoding('utf8')
        res.on('data', (c) => { out += c })
        res.on('end', () => resolve({ status: res.statusCode, body: out, headers: res.headers }))
      })
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '(timeout)' }) })
      req.on('error', (e) => resolve({ status: 0, body: e.message }))
      req.end(data)
    })
  }

  get(pathname) { return this.#request('GET', pathname) }

  /** The `ts` the page was served with. Every apply.cgi post must carry its own page's value. */
  static timestampOf(html) {
    return html.match(/var\s+ts\s*=\s*["'](\d+)["']/)?.[1]
      ?? html.match(/timestamp["'\s=:]+(\d{4,})/)?.[1]
      ?? null
  }

  /** Mirrors the page's own URL building, space and all — jQuery sends it as %20. */
  applyPath(ts, htm = '') { return `/apply.cgi?${htm}%20timestamp=${ts}` }

  /**
   * The firmware answers 400 — not 403 — when a POST's Referer does not name the page owning the
   * form. It is the CSRF check wearing a malformed-request costume, so default the Referer to the
   * owning page rather than the site root.
   */
  apply(fields, ts, htm = '', headers = {}) {
    const body = new URLSearchParams(fields).toString()
    const referer = htm ? `https://${this.host}${htm}` : `https://${this.host}/`
    return this.#request('POST', this.applyPath(ts, htm), body, { Referer: referer, ...headers })
  }

  /**
   * Two posts at most, ever. The firmware locks the whole UI for a minute after a handful of rejected
   * logins, so a retry loop here is strictly worse than a clear failure.
   */
  async login() {
    if (this.authed) return { ok: true, cached: true }
    let r = null
    let ts = null

    for (let attempt = 0; attempt < 2; attempt++) {
      const page = await this.get('/')
      if (page.status !== 200) return { ok: false, reason: `GET / returned ${page.status}` }
      // The login page's own checklogin() contains the literal "unauth.cgi", so matching on that
      // alone flags every healthy page as locked. The lockout page is a ~113b stub with no form —
      // loginWrapper is what actually distinguishes them.
      if (!/loginWrapper/.test(page.body)) return { ok: false, reason: 'router served the unauth stub — 1-minute lockout, wait and retry' }
      ts = NetgearWeb.timestampOf(page.body)
      if (!ts) return { ok: false, reason: 'no timestamp token in the login page' }

      r = await this.apply({ submit_flag: 'admin_login', username: this.user, password: netgearEncode(this.password) }, ts)

      // The first post of a fresh connection can 400 before a session cookie exists; once the router
      // has issued one, the identical request is accepted. Only that case is retried.
      if (r.status !== 400 || !this.cookie) break
    }

    const result = r.body.trim()
    if (result === '5' || /unauth\.cgi/.test(result)) return { ok: false, reason: 'router replied 5 / unauth — credentials rejected', ts }
    if (result === '3' || /multi_login/.test(result)) return { ok: false, reason: 'another device holds the admin session — only one is allowed', ts }
    if (r.status !== 200) return { ok: false, reason: `apply.cgi returned ${r.status}`, ts }

    // Proof rather than inference: an authenticated GET of start.htm is not the login wrapper.
    const start = await this.get('/start.htm')
    this.authed = start.status === 200 && !/id=["']loginWrapper["']/.test(start.body)
    return this.authed ? { ok: true, ts } : { ok: false, reason: 'login accepted but start.htm still served the login wrapper', ts }
  }
}
