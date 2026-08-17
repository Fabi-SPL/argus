#!/usr/bin/env node
// The CLI. Same registry, same guards — a third face on the one core, useful for checking a config
// without attaching an agent or opening a browser.
//
//   argus overview                     every device, does it answer, what does it say it is
//   argus posture                      the one security verdict
//   argus caps [--kind write]          every capability, with its reference
//   argus run <ref> ['{"json":true}']  invoke one capability   (add --confirm to apply a write)
//   argus hub                          serve the web surface
//   argus doctor                       config sanity check, no device contacted

import { loadConfig } from '../src/core/config.mjs'
import { Registry } from '../src/core/registry.mjs'
import { posture } from '../src/core/posture.mjs'
import { ArgusError } from '../src/core/errors.mjs'
import { serveHub } from '../src/hub/server.mjs'

const argv = process.argv.slice(2)
const flags = new Set(argv.filter((a) => a.startsWith('--')))
const args = argv.filter((a) => !a.startsWith('--'))
const [command = 'overview', ...rest] = args

const out = (v) => console.log(typeof v === 'string' ? v : JSON.stringify(v, null, 2))
const kindFlag = argv.find((a) => a.startsWith('--kind='))?.split('=')[1]

const DOT = { ok: '·', unknown: '?', warn: '!', risk: '!!' }

try {
  switch (command) {
    case 'doctor': {
      const config = loadConfig()
      const registry = await Registry.load(config)
      out({
        config: config.paths.config,
        env: config.paths.env,
        site: config.site,
        policy: config.policy,
        devices: registry.listDevices(),
        note: 'no device was contacted — this only checks that the config loads and every driver resolves',
      })
      break
    }

    case 'overview': {
      const registry = await Registry.load(loadConfig())
      out(await registry.probeAll())
      break
    }

    case 'posture': {
      const registry = await Registry.load(loadConfig())
      const p = await posture(registry)
      if (flags.has('--json')) { out(p); break }
      console.log(`\n${p.headline}\n`)
      for (const c of p.checks) console.log(` ${(DOT[c.level] ?? '·').padEnd(3)} ${c.title}\n     ${c.detail ?? ''}`)
      console.log('')
      break
    }

    case 'devices': {
      const registry = await Registry.load(loadConfig())
      out(registry.listDevices())
      break
    }

    case 'caps': {
      const registry = await Registry.load(loadConfig())
      const caps = registry.listCapabilities({ kind: kindFlag })
      if (flags.has('--json')) { out(caps); break }
      for (const c of caps) console.log(`${c.ref.padEnd(38)} ${c.kind.padEnd(9)} ${c.title}`)
      break
    }

    case 'run': {
      const [ref, json] = rest
      if (!ref) throw new ArgusError('INPUT_INVALID', 'usage: argus run <device.capability> [json-args] [--confirm]')
      const registry = await Registry.load(loadConfig())
      out(await registry.invoke(ref, json ? JSON.parse(json) : {}, { confirm: flags.has('--confirm') }))
      break
    }

    case 'hub': {
      const { url, config } = await serveHub()
      console.error(`argus hub — ${url}  (${config.devices.length} devices, ctrl-c to stop)`)
      break
    }

    default:
      throw new ArgusError('INPUT_INVALID', `unknown command "${command}" — try overview, posture, devices, caps, run, hub, doctor`)
  }
} catch (e) {
  if (e instanceof ArgusError) { console.error(`${e.code}: ${e.message}`); if (e.detail && Object.keys(e.detail).length) console.error(JSON.stringify(e.detail, null, 2)) }
  else console.error(e.message)
  process.exit(1)
}
