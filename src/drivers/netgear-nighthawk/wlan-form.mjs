// Rebuilding the wireless page's POST body, because SOAP will not rename a 5 GHz band: every
// Set5G*SSID / Set5G*WLANWPAPSKByPassphrase answers 402 across every parameter set worth trying,
// on a SOAP session and a web session alike, while Set5G*Enable answers 000 with one field.
//
// The form is all-or-nothing — apply.cgi takes the whole thing — and it cannot be read off the
// markup alone:
//
//   • channel <select>s render with zero <option>s; JS builds them at load time
//   • passphrase inputs render empty; JS fills them from wla_wpa2_psk and friends
//   • each password box has a *_press_flag that JS sets to 1 when the user types in it, and the
//     firmware uses that flag to decide whether the submitted key replaces the stored one
//   • check_wlan() copies every visible control into a parallel set of ~70 hidden mirror fields
//     (wl_ssid, wla_hidden_wlan_channel, wla_hidden_sec_type, …) that all ship EMPTY in the markup
//
// So the page's `var` block is the router's real state, and this reconstructs the body from it.
//
// ⚠️ STATUS: apply.cgi still answers 400 / 382 bytes to the reconstructed no-op body on firmware
// V1.0.19.172. Eliminated so far, each with a control run: Referer (4 variants), URL and query shape
// (7 variants including the proven login shape), body size (28b–2998b), field count (1–137), repeat
// posts, fresh vs reused timestamp, keep-alive, content type (5 variants — including text/plain,
// which returned the identical 382-byte body, so rejection precedes body parsing), and the hidden
// mirror fields filled in below. The decisive control: admin_login succeeds on the identical URL,
// headers and cookie — only the body and submit_flag differ. Reading the form works and is useful on
// its own; writing through it does not, yet. Left in the tree with the findings intact rather than
// deleted, because the next person to try deserves the eliminations.

const SECTYPE = { 1: 'Disable', 2: 'WEP', 3: 'WPA-PSK', 4: 'WPA2-PSK', 5: 'AUTO-PSK', 6: 'WPA-Enterprise', 7: 'WPA3-PSK', 8: 'AUTO-WPA3-PSK' }

export const PAGE = '/WLG_wireless.htm'

/** Pulls `var name = "value";` / `var name = 123;` out of the page. */
function readVars(html) {
  const vars = new Map()
  for (const m of html.matchAll(/\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(["'])([\s\S]*?)\2\s*;/g)) {
    if (m[3].length <= 200) vars.set(m[1], m[3])
  }
  for (const m of html.matchAll(/\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)\s*;/g)) {
    if (!vars.has(m[1])) vars.set(m[1], m[2])
  }
  return vars
}

/**
 * A plain parse of the form finds 126 controls; the browser submits 136. The missing ten are the
 * ones the page emits from document.write(), so unwrap those string literals into markup first.
 */
const unwrapWrites = (html) => html.replace(/document\.write\(\s*(['"])([\s\S]*?)\1\s*\)/g,
  (_, q, body) => body.replace(/\\'/g, "'").replace(/\\"/g, '"').replace(/\\n/g, '\n'))

/** Every named control inside the apply.cgi form, with the value the markup ships. */
function readControls(rawHtml) {
  const html = unwrapWrites(rawHtml)
  const form = html.match(/<form[^>]*action=["'][^"']*apply\.cgi[^"']*["'][^>]*>([\s\S]*?)<\/form>/i)?.[1] ?? ''
  const out = new Map()
  for (const m of form.matchAll(/<input[^>]*>/gi)) {
    const t = m[0]
    const name = t.match(/name=["']([^"']+)["']/i)?.[1]
    if (!name) continue
    const type = (t.match(/type=["']([^"']+)["']/i)?.[1] ?? 'text').toLowerCase()
    if (type === 'button' || type === 'submit') continue
    const value = t.match(/value=["']([^"']*)["']/i)?.[1] ?? ''
    if (type === 'radio') {
      if (/\schecked\b/i.test(t)) out.set(name, value)
      else if (!out.has(name)) out.set(name, out.get(name) ?? '')
      continue
    }
    if (type === 'checkbox') { out.set(name, /\schecked\b/i.test(t) ? (value || '1') : ''); continue }
    out.set(name, value)
  }
  for (const m of form.matchAll(/<select[^>]*name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/select>/gi)) {
    const opts = [...m[2].matchAll(/<option[^>]*value=["']([^"']*)["'][^>]*>/gi)]
    const sel = opts.find((o) => /\sselected\b/i.test(o[0]))?.[1]
    out.set(m[1], sel ?? opts[0]?.[1] ?? '')
  }
  return out
}

/**
 * Fills the hidden mirrors check_wlan() would populate. Prefixes: wl_ = 2.4 GHz, wla_ = the first
 * 5 GHz band, wla_2nd_ = the second, which is echoed back exactly as found and never derived.
 */
function fillMirrors(fields, v) {
  const set = (k, val) => { if (val !== undefined && val !== null) fields.set(k, String(val)) }
  const region = v('wl_get_countryA', fields.get('WRegion') ?? '')

  const bands = [
    { p: 'wl_', ssid: 'ssid', ch: 'w_channel', bc: 'ssid_bc', mode: 'wl_mode', sec: 'wl_sectype', psk: 'wl_wpa2_psk' },
    { p: 'wla_', ssid: 'ssid_an', ch: 'w_channel_an', bc: 'ssid_bc_an', mode: 'wla_mode', sec: 'wla_sectype', psk: 'wla_wpa2_psk' },
    { p: 'wla_2nd_', ssid: 'ssid_tri', ch: 'w_channel_tri', bc: 'ssid_bc_tri', mode: 'wla_2nd_mode', sec: 'wla_2nd_sectype', psk: 'wla_2nd_wpa2_psk' },
  ]

  for (const b of bands) {
    set(`${b.p}ssid`, fields.get(b.ssid))
    set(`${b.p}WRegion`, region)
    set(`${b.p}enable_ssid_broadcast`, fields.get(b.bc) ? '1' : '0')
    set(`${b.p}hidden_wlan_channel`, fields.get(b.ch))
    set(`${b.p}hidden_wlan_mode`, v(b.mode))
    set(`${b.p}hidden_sec_type`, v(b.sec, '4'))
    set(`${b.p}hidden_wpa_psk`, v(b.psk))
    if (b.p !== 'wl_') set(`${b.p}hidden_sel_dfs`, '1')
  }

  set('wl_apply_flag', '1')
  set('change_region_flag', '0')
  set('hid_enable_smart_connect', v('hid_enable_smart_connect', '0'))
}

/** The router's current wireless state as a complete, submittable field map. */
export async function readWlanState(web) {
  const r = await web.get(PAGE)
  if (r.status !== 200 || /loginWrapper/.test(r.body)) {
    throw new Error(`${PAGE} returned ${r.status}${/loginWrapper/.test(r.body) ? ' (not authenticated)' : ''}`)
  }
  const ts = r.body.match(/action=["'][^"']*apply\.cgi\?[^"']*timestamp=(\d+)/)?.[1]
  if (!ts) throw new Error('no timestamp on the wireless form')

  const vars = readVars(r.body)
  const fields = new Map(readControls(r.body))
  const v = (k, d = '') => vars.get(k) ?? d

  fields.set('submit_flag', 'wlan')

  const put = (k, val) => { if (val !== undefined && val !== null) fields.set(k, String(val)) }
  put('w_channel', v('wl_get_channel', '0'))
  put('w_channel_an', v('wla_get_channel'))
  put('w_channel_tri', v('wla_2nd_get_channel'))
  put('opmode', v('wl_mode', fields.get('opmode')))
  put('opmode_an', v('wla_mode', fields.get('opmode_an')))
  put('opmode_tri', v('wla_2nd_mode', fields.get('opmode_tri')))
  put('security_type', SECTYPE[v('wl_sectype', '4')])
  put('security_type_an', SECTYPE[v('wla_sectype', '4')])
  put('security_type_tri', SECTYPE[v('wla_2nd_sectype', '4')])
  put('passphrase', v('wl_wpa2_psk', fields.get('passphrase')))
  put('passphrase_an', v('wla_wpa2_psk'))
  put('passphrase_tri', v('wla_2nd_wpa2_psk'))

  // the firmware keeps the stored key unless the matching press flag says the box was edited
  for (const f of ['wpa2_press_flag', 'wla_wpa2_press_flag', 'wla_2nd_wpa2_press_flag']) put(f, '0')

  fillMirrors(fields, v)

  const bands = {
    '2.4': { ssid: fields.get('ssid'), channel: fields.get('w_channel'), security: SECTYPE[v('wl_sectype')] ?? null, passphrase: v('wl_wpa2_psk') },
    '5g1': { ssid: fields.get('ssid_an'), channel: fields.get('w_channel_an'), security: SECTYPE[v('wla_sectype')] ?? null, passphrase: v('wla_wpa2_psk') },
    '5g2': { ssid: fields.get('ssid_tri'), channel: fields.get('w_channel_tri'), security: SECTYPE[v('wla_2nd_sectype')] ?? null, passphrase: v('wla_2nd_wpa2_psk') },
  }

  return { ts, fields, bands }
}

/** Applies overrides to a state's field map without mutating it. */
export function withOverrides(fields, overrides) {
  const next = new Map(fields)
  for (const [k, val] of Object.entries(overrides)) next.set(k, String(val))
  return next
}

/** Names of fields whose value differs between two maps — the pre-flight safety check. */
export function diffFields(a, b) {
  const names = new Set([...a.keys(), ...b.keys()])
  return [...names].filter((n) => (a.get(n) ?? '') !== (b.get(n) ?? '')).sort()
}

export const applyWlan = (web, fields, ts) => web.apply(Object.fromEntries(fields), ts, PAGE)
