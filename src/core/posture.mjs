// "Am I actually protected right now?" — asked once, answered from every device at the same moment.
//
// This is the reason Argus aggregates rather than links out. The answer lives in four places that
// never agree on a vocabulary: the gateway knows about the WAN and its own hotspot, the access
// points know what encryption is on air, the VPN knows whether traffic is leaving through a tunnel,
// and only a person holding all three at once can say whether the house is covered.
//
// Every check is read-only, runs in parallel, and degrades honestly: a device that cannot be reached
// produces an `unknown` check, never a silent pass. An unknown is not a green — the verdict says so.

const LEVELS = { ok: 0, unknown: 1, warn: 2, risk: 3 }
const worst = (checks) => checks.reduce((acc, c) => (LEVELS[c.level] > LEVELS[acc] ? c.level : acc), 'ok')

const check = (level, id, title, detail, extra = {}) => ({ level, id, title, detail, ...extra })

/** Runs one capability if the device has it, and turns any failure into an `unknown` check. */
async function tryInvoke(registry, ref) {
  try { return { ok: true, data: (await registry.invoke(ref)).result } }
  catch (e) { return { ok: false, error: e.message } }
}

const OPEN_SECURITY = /^(none|open|disable|wep)/i

async function gatewayChecks(registry, device) {
  const out = []
  const r = await tryInvoke(registry, `${device.id}.status`)
  if (!r.ok) return [check('unknown', `${device.id}.reachable`, `${device.title} did not answer`, r.error, { device: device.id })]
  const s = r.data

  out.push(check('ok', `${device.id}.identity`, `${s.model ?? device.title} online`,
    `firmware ${s.firmware ?? 'unknown'} · internet ${s.internet ?? 'unknown'}`, { device: device.id }))

  if (s.hotspot) {
    out.push(check('warn', `${device.id}.hotspot`, 'Carrier hotspot is broadcasting from your line',
      'The provider\'s public hotspot keeps this radio powered and visible even when its own WiFi reads as off. Strangers associate to it, on your hardware.',
      { device: device.id }))
  }
  if (s.radioLikelyLive && !s.wifi24?.enabled && !s.wifi5?.enabled) {
    out.push(check('warn', `${device.id}.ghostradio`, 'A radio is live that the config says is off',
      'Config flags and the air disagree here — trust an air scan over the flag.', { device: device.id }))
  }
  return out
}

async function apChecks(registry, device) {
  const out = []
  const live = await tryInvoke(registry, `${device.id}.radios.read`)
  const bands = await tryInvoke(registry, `${device.id}.bands.read`)

  if (!live.ok && !bands.ok) {
    return [check('unknown', `${device.id}.reachable`, `${device.title} did not answer`, live.error ?? bands.error, { device: device.id })]
  }

  const radios = live.ok ? live.data : []
  for (const r of radios) {
    if (r.encryption && OPEN_SECURITY.test(r.encryption)) {
      out.push(check('risk', `${device.id}.${r.interface}.open`, `"${r.ssid}" is unencrypted or on WEP`,
        `${r.interface} reports ${r.encryption}. Anyone in range is on your LAN.`, { device: device.id }))
    }
  }

  for (const b of bands.ok ? bands.data : []) {
    if (b.security && OPEN_SECURITY.test(b.security)) {
      out.push(check('risk', `${device.id}.${b.band}.open`, `"${b.ssid}" is unencrypted`,
        `Band ${b.band} reports ${b.security}.`, { device: device.id }))
    }
    if (b.broadcast === '0') {
      out.push(check('ok', `${device.id}.${b.band}.hidden`, `"${b.ssid}" is hidden`,
        'Hidden SSIDs are not a security control, but they are intentional here.', { device: device.id }))
    }
  }

  const guest = radios.filter((r) => /gastzugang|guest/i.test(r.ssid ?? ''))
  if (guest.length) {
    out.push(check('warn', `${device.id}.guest`, `Guest network is live on ${device.title}`,
      `${guest.map((g) => `"${g.ssid}"`).join(', ')} — fine if deliberate, worth killing if it came back on its own.`, { device: device.id }))
  }

  // an interface with no SSID is a phy with nothing bound to it, not a network — leave it out
  const named = [
    ...radios.filter((r) => r.ssid).map((r) => `${r.ssid} (${r.encryption ?? 'unknown'})`),
    ...(bands.ok ? bands.data : []).filter((b) => b.ssid && b.enabled !== '0').map((b) => `${b.ssid} (${b.security ?? 'unknown'})`),
  ]
  out.push(check('ok', `${device.id}.wifi`, `${device.title}: ${named.length} network${named.length === 1 ? '' : 's'} on air`,
    named.length ? named.join(' · ') : 'nothing broadcasting', { device: device.id }))

  return out
}

async function vpnChecks(registry, device) {
  const out = []
  const local = await tryInvoke(registry, `${device.id}.local.status`)

  if (local.ok && local.data?.backendState) {
    const s = local.data
    if (s.backendState !== 'Running') {
      out.push(check('warn', `${device.id}.backend`, 'Tailscale is installed but not running',
        `backend state: ${s.backendState}`, { device: device.id }))
    } else if (s.usingExitNode) {
      out.push(check('ok', `${device.id}.exitnode`, `Traffic is leaving through ${s.usingExitNode.name}`,
        'This machine is routing through an exit node.', { device: device.id }))
    } else {
      out.push(check('warn', `${device.id}.exitnode`, 'No exit node — traffic leaves through your own line',
        s.exitNodeOptions?.length
          ? `${s.exitNodeOptions.length} exit node(s) available: ${s.exitNodeOptions.map((o) => o.name).join(', ')}`
          : 'No exit nodes are advertised in this tailnet.',
        { device: device.id }))
    }
    for (const h of s.health ?? []) {
      out.push(check('warn', `${device.id}.health`, 'Tailscale reports a health warning', h, { device: device.id }))
    }
  } else {
    out.push(check('unknown', `${device.id}.local`, 'No local Tailscale state',
      local.error ?? 'the CLI is not on this machine — remote tailnet checks still ran', { device: device.id }))
  }

  const devices = await tryInvoke(registry, `${device.id}.devices.list`)
  if (devices.ok) {
    const expiring = devices.data.filter((d) => d.expires && !d.keyExpiryDisabled
      && new Date(d.expires).getTime() - Date.now() < 14 * 864e5)
    if (expiring.length) {
      out.push(check('warn', `${device.id}.keyexpiry`, `${expiring.length} device key(s) expire within two weeks`,
        expiring.map((d) => d.name).join(', '), { device: device.id }))
    }
    const stale = devices.data.filter((d) => !d.online)
    out.push(check('ok', `${device.id}.tailnet`, `Tailnet: ${devices.data.length} devices, ${devices.data.length - stale.length} online`,
      stale.length ? `offline: ${stale.map((d) => d.name).join(', ')}` : 'all online', { device: device.id }))
  }

  return out
}

const ROLE_CHECKS = { gateway: gatewayChecks, ap: apChecks, vpn: vpnChecks }

/** Infers a role when the config does not state one, so posture works on a config nobody annotated. */
function roleOf(device) {
  if (device.role) return device.role
  if (device.driver === 'tailscale') return 'vpn'
  if (device.driver === 'telekom-speedport') return 'gateway'
  return 'ap'
}

export async function posture(registry) {
  const devices = registry.listDevices()
  const results = await Promise.all(devices.map(async (d) => {
    const fn = ROLE_CHECKS[roleOf(d)] ?? apChecks
    try { return await fn(registry, d) }
    catch (e) { return [check('unknown', `${d.id}.error`, `${d.title} check failed`, e.message, { device: d.id })] }
  }))

  const checks = results.flat()
  const verdict = worst(checks)
  const counts = checks.reduce((a, c) => ({ ...a, [c.level]: (a[c.level] ?? 0) + 1 }), {})

  return {
    verdict,
    headline: {
      ok: 'Nothing exposed that Argus can see.',
      unknown: 'Mostly clear, but something did not answer — treat this as incomplete.',
      warn: 'Working, with things worth looking at.',
      risk: 'Something is open right now.',
    }[verdict],
    counts,
    checks: checks.sort((a, b) => LEVELS[b.level] - LEVELS[a.level]),
    checkedAt: new Date().toISOString(),
  }
}
