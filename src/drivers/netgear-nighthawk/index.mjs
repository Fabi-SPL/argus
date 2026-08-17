// NETGEAR Nighthawk (RAX / R-series firmware). Two protocols, because neither is sufficient alone:
// SOAP reads everything and toggles radios, but refuses to rename a 5 GHz band; the web UI's
// apply.cgi form is the only path the vendor's own app uses for that, and it currently rejects a
// reconstructed body (see wlan-form.mjs for the full elimination list).
//
// Bands are named '2.4', '5g1', '5g2' throughout. Which one is which varies by model, and on a
// tri-band unit one of them is usually carrying something you must not interrupt — pin that band in
// the device's `guard` block in argus.config.json and every write capability will refuse it.

import { z } from 'zod'
import { defineDriver, defineCapability } from '../../core/driver.mjs'
import { fingerprint } from '../../core/redact.mjs'
import { NetgearSoap } from './soap.mjs'
import { NetgearWeb } from './web.mjs'
import { readWlanState, withOverrides, diffFields, applyWlan, PAGE } from './wlan-form.mjs'

const BAND = z.enum(['2.4', '5g1', '5g2'])

export default defineDriver({
  type: 'netgear-nighthawk',
  title: 'NETGEAR Nighthawk (RAX / R series)',
  vendor: 'NETGEAR',
  requires: ['host', 'password'],
  optional: ['user'],

  create(device) {
    const cfg = { host: device.host, user: device.user ?? 'admin', password: device.password }
    const soap = new NetgearSoap(cfg)
    const web = new NetgearWeb(cfg)

    const soapSession = async () => {
      const l = await soap.login()
      if (!l.ok) throw new Error(`SOAP login refused (code ${l.code ?? l.status})`)
      return soap
    }
    const webSession = async () => {
      const l = await web.login()
      if (!l.ok) throw new Error(`web login refused — ${l.reason}`)
      return web
    }

    return {
      async probe() {
        const l = await soap.login()
        if (!l.ok) return { ok: false, error: `SOAP login refused (code ${l.code ?? l.status})` }
        const info = await soap.deviceInfo()
        return {
          ok: true,
          identity: {
            model: info.model,
            firmware: info.firmware,
            mode: info.deviceMode === '0' ? 'router' : info.deviceMode === '1' ? 'access point' : `mode ${info.deviceMode}`,
          },
        }
      },

      capabilities: [
        defineCapability({
          name: 'info',
          title: 'Device info',
          kind: 'read',
          input: z.object({}),
          run: async () => (await soapSession()).deviceInfo(),
        }),

        defineCapability({
          name: 'bands.read',
          title: 'Per-band wireless state',
          kind: 'read',
          input: z.object({}),
          run: async () => (await soapSession()).bands(),
        }),

        defineCapability({
          name: 'clients.list',
          title: 'Attached devices',
          kind: 'read',
          input: z.object({}),
          run: async () => (await soapSession()).attachedDevices(),
        }),

        defineCapability({
          name: 'keys.fingerprint',
          title: 'Compare passphrases without revealing them',
          kind: 'diagnose',
          input: z.object({}),
          async run() {
            const keys = await (await soapSession()).securityKeys()
            return keys.map(({ band, ok, code, passphrase }) => ({ band, ok, code, ...(fingerprint(passphrase) ?? { fp: null, length: 0 }) }))
          },
        }),

        defineCapability({
          name: 'radio.set',
          title: 'Turn one band on or off',
          kind: 'write',
          input: z.object({
            band: BAND,
            on: z.boolean(),
            dryRun: z.boolean().default(true),
          }),
          guardTarget: ({ band }) => ({ band }),
          async run({ band, on, dryRun }) {
            const s = await soapSession()
            const before = await s.bands()
            if (dryRun) return { mode: 'dry run', would: `${band} radio → ${on ? 'on' : 'off'}`, before }
            const r = await s.setRadio(band, on)
            if (!r.ok) throw new Error(`setRadio refused (code ${r.code})`)
            return { mode: 'applied', band, on, after: await s.bands() }
          },
        }),

        defineCapability({
          name: 'ssid.set',
          title: 'Rename a band (2.4 GHz only on current firmware)',
          kind: 'write',
          input: z.object({
            band: BAND,
            ssid: z.string().min(1).max(32),
            dryRun: z.boolean().default(true),
          }),
          guardTarget: ({ band, ssid }) => ({ band, ssid }),
          async run({ band, ssid, dryRun }) {
            const s = await soapSession()
            const before = await s.bands()
            const current = before.find((b) => b.band === band)
            if (dryRun) {
              return {
                mode: 'dry run',
                would: `${band}: "${current?.ssid}" → "${ssid}"`,
                ...(band === '2.4' ? {} : { warning: 'firmware V1.0.19.172 answers 402 to every 5 GHz SSID setter — this will very likely fail' }),
              }
            }
            const keys = await s.securityKeys()
            const passphrase = keys.find((k) => k.band === band)?.passphrase
            if (!passphrase) throw new Error(`cannot read the ${band} passphrase, so renaming would clear it — refusing`)

            await s.configStart()
            const r = await s.setSsidAndKey(band, ssid, passphrase)   // both in one call; passing the key back keeps it
            await s.configFinish()
            if (!r.ok) throw new Error(`setSsidAndKey refused (code ${r.code})${r.code === '402' ? ' — the known 5 GHz refusal' : ''}`)
            return { mode: 'applied', band, ssid, after: await s.bands() }
          },
        }),

        defineCapability({
          name: 'wlanform.read',
          title: 'Reconstruct the wireless page POST body',
          kind: 'diagnose',
          input: z.object({}),
          async run() {
            const { ts, fields, bands } = await readWlanState(await webSession())
            return {
              page: PAGE,
              timestamp: ts,
              fieldCount: fields.size,
              bands: Object.fromEntries(Object.entries(bands).map(([k, b]) => [k, { ...b, passphrase: undefined, key: fingerprint(b.passphrase) }])),
            }
          },
        }),

        defineCapability({
          name: 'wlanform.apply',
          title: 'Post the wireless form (currently rejected — see wlan-form.mjs)',
          kind: 'write',
          input: z.object({
            overrides: z.record(z.string(), z.string()).default({}).describe('Field values to change. Empty object posts an exact no-op.'),
            dryRun: z.boolean().default(true),
          }),
          async run({ overrides, dryRun }) {
            const w = await webSession()
            const { ts, fields } = await readWlanState(w)
            const next = withOverrides(fields, overrides)
            const changed = diffFields(fields, next)
            if (dryRun) return { mode: 'dry run', timestamp: ts, fieldCount: next.size, changed }

            const r = await applyWlan(w, next, ts)
            return {
              mode: 'attempted',
              status: r.status,
              bytes: r.body.length,
              changed,
              ...(r.status === 400
                ? { known: 'apply.cgi answers 400/382b to a reconstructed body on this firmware; every body-shaped hypothesis has been eliminated' }
                : {}),
            }
          },
        }),

        defineCapability({
          name: 'soap.probe',
          title: 'Fire a SOAP action verbatim',
          kind: 'diagnose',
          input: z.object({
            service: z.string().describe('Short name (deviceInfo, deviceConfig, wlan, lan, wan, parental) or a full urn.'),
            method: z.string(),
            inner: z.string().default('').describe('Raw XML for the method body.'),
          }),
          run: async ({ service, method, inner }) => (await soapSession()).probe(service, method, inner),
        }),
      ],
    }
  },
})
