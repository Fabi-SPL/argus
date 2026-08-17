// The driver contract. A driver is one file that knows how to talk to one family of devices, and
// nothing else in Argus knows anything about that family — every protocol crime a consumer router
// commits (SOAP over a self-signed cert, ubus JSON-RPC, a form POST whose hidden fields the page's
// own JavaScript fills in) is confined to the driver that needs it.
//
// A driver exports a default object:
//
//   export default defineDriver({
//     type: 'my-router',                       // matches "driver" in argus.config.json
//     title: 'My Router (AC1200 series)',
//     vendor: 'Acme',
//     requires: ['host', 'password'],          // config keys that must be present
//     optional: ['user'],
//     create(device, ctx) {                    // device = the resolved config entry
//       return {
//         async probe() { return { ok: true, identity: { model, firmware } } },
//         capabilities: [ ... ],
//       }
//     },
//   })
//
// and each capability is:
//
//   defineCapability({
//     name: 'wifi.read',                       // dotted, stable, lowercase
//     title: 'Read wireless state',
//     kind: 'read',                            // read | write | diagnose | restart
//     input: z.object({}),                     // zod schema; validated before run() is called
//     guardTarget: (args) => ({ band: args.band }),   // optional, only for writes
//     async run(args, ctx) { ... },
//   })
//
// `kind` is the whole permission model. `read` and `diagnose` run freely. `write` needs an explicit
// confirm from the caller when policy.confirmWrites is on, and `restart` is hidden entirely unless
// policy.allowRestart is on. That is the only place risk is decided — a driver never asks.

import { fail } from './errors.mjs'

export const KINDS = ['read', 'diagnose', 'write', 'restart']

export function defineCapability(cap) {
  if (!cap.name) fail('DRIVER_UNKNOWN', 'capability has no name')
  if (!KINDS.includes(cap.kind)) fail('DRIVER_UNKNOWN', `capability "${cap.name}" has kind "${cap.kind}", expected one of ${KINDS.join(', ')}`)
  if (typeof cap.run !== 'function') fail('DRIVER_UNKNOWN', `capability "${cap.name}" has no run()`)
  return { title: cap.name, input: null, guardTarget: null, ...cap }
}

export function defineDriver(driver) {
  if (!driver.type) fail('DRIVER_UNKNOWN', 'driver has no type')
  if (typeof driver.create !== 'function') fail('DRIVER_UNKNOWN', `driver "${driver.type}" has no create()`)
  return { requires: [], optional: [], vendor: null, ...driver }
}

/** Shared by every driver so a missing host or password fails identically across vendors. */
export function requireConfig(device, keys) {
  const missing = keys.filter((k) => device[k] === undefined || device[k] === null || device[k] === '')
  if (missing.length) {
    fail('CONFIG_INVALID', `device "${device.id}" is missing required config: ${missing.join(', ')}`,
      { device: device.id, missing })
  }
}
