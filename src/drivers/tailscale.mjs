// Tailscale, as just another Argus driver — which is the point of the driver contract: a mesh VPN
// and a powerline adapter answer the same kind of question ("what is my network doing, and am I
// covered") and should be reachable the same way.
//
// Three surfaces, and it matters which one can do what:
//
//   • the REST API (api.tailscale.com) reads the tailnet and approves a device AS an exit node. It
//     CANNOT change which exit node a client routes through. That is the single most-assumed-wrong
//     thing about this API and the reason exitnode.* below does not go through it.
//   • the LocalAPI is strictly device-local — only the machine Argus runs on.
//   • each client also serves a web interface on port 5252. That is the only remote path to switching
//     a device's chosen exit node, and it requires the device to be tagged and the tailnet policy to
//     grant `canEdit: exitNodes`, with the client started via `tailscale set --webclient`.
//
// So: read the whole tailnet remotely, switch this machine's exit node locally, and for a remote
// device either use its :5252 interface (probe it first — the endpoint shape varies by client
// version) or SSH and run `tailscale set --exit-node <name>`, which is what ssh.exitnode.set does.

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { z } from 'zod'
import { defineDriver, defineCapability } from '../core/driver.mjs'

const run = promisify(execFile)
const API = 'https://api.tailscale.com/api/v2'
const EXIT_ROUTES = ['0.0.0.0/0', '::/0']

async function api(token, path, { method = 'GET', body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(20_000),
  })
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { /* keep the raw text below */ }
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${data?.message ?? text.slice(0, 200)}`)
  return data
}

const advertisesExit = (routes) => EXIT_ROUTES.some((r) => (routes ?? []).includes(r))

/**
 * The tailnet /devices response has no `online` field — that is a LocalAPI concept, and reading it
 * here silently marks every device offline. `connectedToControl` is the equivalent, and `lastSeen`
 * is the fallback for older responses that carry neither.
 */
const isOnline = (d) => d.connectedToControl ?? d.online
  ?? (d.lastSeen ? Date.now() - new Date(d.lastSeen).getTime() < 5 * 60_000 : null)

/**
 * Routes are NOT part of the device list — they only come from /device/{id}/routes, one call each.
 * Filtering the list response on `advertisedRoutes` therefore matches nothing, ever, and an empty
 * exit-node list reads as "you have none" rather than "this was never asked".
 */
async function routesOf(apiKey, devices) {
  return Promise.all(devices.map(async (d) => ({
    device: d,
    routes: await api(apiKey, `/device/${d.id}/routes`).catch(() => null),
  })))
}

/** Runs the local tailscale binary. Absent CLI is reported plainly, not thrown as a mystery. */
async function cli(bin, args) {
  try {
    const { stdout } = await run(bin, args, { timeout: 25_000, windowsHide: true })
    return { ok: true, stdout: stdout.trim() }
  } catch (e) {
    if (e.code === 'ENOENT') return { ok: false, error: `no tailscale binary at "${bin}" — set cliPath on this device in argus.config.json` }
    return { ok: false, error: (e.stderr || e.message || '').trim() }
  }
}

export default defineDriver({
  type: 'tailscale',
  title: 'Tailscale (mesh VPN)',
  vendor: 'Tailscale',
  requires: ['tailnet', 'apiKey'],
  optional: ['cliPath', 'sshUser'],

  create(device) {
    const { tailnet, apiKey } = device
    const bin = device.cliPath ?? 'tailscale'
    const t = (path) => `/tailnet/${encodeURIComponent(tailnet)}${path}`

    return {
      async probe() {
        try {
          const { devices } = await api(apiKey, t('/devices'))
          const online = devices.filter(isOnline).length
          return { ok: true, identity: { tailnet, devices: devices.length, online } }
        } catch (e) { return { ok: false, error: e.message } }
      },

      capabilities: [
        defineCapability({
          name: 'devices.list',
          title: 'Every device in the tailnet',
          kind: 'read',
          input: z.object({
            onlineOnly: z.boolean().default(false),
            withRoutes: z.boolean().default(false)
              .describe('Also resolve exit-node status. Costs one extra API call per device.'),
          }),
          async run({ onlineOnly, withRoutes }) {
            const { devices: all } = await api(apiKey, t('/devices'))
            const devices = all.filter((d) => !onlineOnly || isOnline(d))
            // null, not false: without the per-device routes call this is genuinely unknown, and a
            // confident `false` here is what made exitnodes.list look empty in the first place.
            const routes = withRoutes
              ? new Map((await routesOf(apiKey, devices)).map(({ device, routes: r }) => [device.id, r]))
              : null
            return devices
              .map((d) => ({
                id: d.id,
                name: d.name,
                hostname: d.hostname,
                os: d.os,
                addresses: d.addresses,
                online: isOnline(d),
                lastSeen: d.lastSeen,
                tags: d.tags ?? [],
                advertisesExitNode: routes ? advertisesExit(routes.get(d.id)?.advertisedRoutes) : null,
                updateAvailable: d.updateAvailable ?? null,
                keyExpiryDisabled: d.keyExpiryDisabled ?? null,
                expires: d.expires,
              }))
          },
        }),

        defineCapability({
          name: 'exitnodes.list',
          title: 'Exit nodes, and whether each is actually approved',
          kind: 'read',
          input: z.object({}),
          async run() {
            const { devices } = await api(apiKey, t('/devices'))
            return (await routesOf(apiKey, devices))
              .filter(({ routes }) => advertisesExit(routes?.advertisedRoutes) || advertisesExit(routes?.enabledRoutes))
              .map(({ device: d, routes }) => ({
                id: d.id,
                name: d.name,
                online: isOnline(d),
                advertised: advertisesExit(routes?.advertisedRoutes),
                approved: advertisesExit(routes?.enabledRoutes),
                usable: Boolean(isOnline(d)) && advertisesExit(routes?.enabledRoutes),
              }))
          },
        }),

        defineCapability({
          name: 'routes.read',
          title: 'Advertised vs approved routes for one device',
          kind: 'read',
          input: z.object({ deviceId: z.string() }),
          run: ({ deviceId }) => api(apiKey, `/device/${deviceId}/routes`),
        }),

        defineCapability({
          name: 'routes.approve',
          title: 'Approve a device as an exit node or subnet router',
          kind: 'write',
          input: z.object({
            deviceId: z.string(),
            routes: z.array(z.string()).describe('The full enabled-routes set. Include 0.0.0.0/0 and ::/0 to approve as an exit node.'),
            dryRun: z.boolean().default(true),
          }),
          async run({ deviceId, routes, dryRun }) {
            const before = await api(apiKey, `/device/${deviceId}/routes`)
            if (dryRun) return { mode: 'dry run', before, would: routes }
            const after = await api(apiKey, `/device/${deviceId}/routes`, { method: 'POST', body: { routes } })
            return { mode: 'applied', before, after }
          },
        }),

        defineCapability({
          name: 'acl.read',
          title: 'Tailnet policy file',
          kind: 'read',
          input: z.object({}),
          async run() {
            const acl = await api(apiKey, t('/acl'))
            const text = JSON.stringify(acl)
            return {
              acl,
              // the grant that decides whether remote exit-node switching is possible at all
              grantsExitNodeEditing: /canEdit[^}]*exitNodes|exitNodes[^}]*canEdit/.test(text),
            }
          },
        }),

        defineCapability({
          name: 'local.status',
          title: 'This machine\'s Tailscale status',
          kind: 'read',
          input: z.object({}),
          async run() {
            const r = await cli(bin, ['status', '--json'])
            if (!r.ok) return r
            const s = JSON.parse(r.stdout)
            const exitNode = Object.values(s.Peer ?? {}).find((p) => p.ExitNode)
            return {
              backendState: s.BackendState,
              self: { name: s.Self?.HostName, addresses: s.Self?.TailscaleIPs, online: s.Self?.Online },
              usingExitNode: exitNode ? { name: exitNode.HostName, dnsName: exitNode.DNSName, addresses: exitNode.TailscaleIPs } : null,
              exitNodeOptions: Object.values(s.Peer ?? {}).filter((p) => p.ExitNodeOption).map((p) => ({ name: p.HostName, online: p.Online })),
              health: s.Health ?? [],
            }
          },
        }),

        defineCapability({
          name: 'local.exitnode.set',
          title: 'Route this machine through an exit node (or stop)',
          kind: 'write',
          input: z.object({
            node: z.string().nullable().describe('Exit node name or IP. Pass null to route directly again.'),
            allowLanAccess: z.boolean().default(true).describe('Keep the local network reachable while the tunnel is up.'),
            dryRun: z.boolean().default(true),
          }),
          async run({ node, allowLanAccess, dryRun }) {
            const args = node
              ? ['set', `--exit-node=${node}`, `--exit-node-allow-lan-access=${allowLanAccess}`]
              : ['set', '--exit-node=']
            if (dryRun) return { mode: 'dry run', would: `${bin} ${args.join(' ')}` }
            const r = await cli(bin, args)
            if (!r.ok) return { mode: 'failed', ...r }
            const after = await cli(bin, ['status', '--json'])
            const s = after.ok ? JSON.parse(after.stdout) : null
            const exit = s && Object.values(s.Peer ?? {}).find((p) => p.ExitNode)
            return { mode: 'applied', usingExitNode: exit ? exit.HostName : null }
          },
        }),

        defineCapability({
          name: 'ssh.exitnode.set',
          title: 'Change another machine\'s exit node over Tailscale SSH',
          kind: 'write',
          input: z.object({
            host: z.string().describe('Tailscale hostname or IP of the machine to change.'),
            node: z.string().nullable(),
            user: z.string().optional(),
            dryRun: z.boolean().default(true),
          }),
          async run({ host, node, user, dryRun }) {
            const target = `${user ?? device.sshUser ?? 'root'}@${host}`
            const remote = node ? `tailscale set --exit-node=${node}` : 'tailscale set --exit-node='
            if (dryRun) return { mode: 'dry run', would: `ssh ${target} ${remote}` }
            const r = await cli('ssh', ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', target, remote])
            return r.ok ? { mode: 'applied', host, node, output: r.stdout } : { mode: 'failed', ...r }
          },
        }),

        defineCapability({
          name: 'webclient.probe',
          title: 'Check whether a device exposes its :5252 web interface',
          kind: 'diagnose',
          input: z.object({
            address: z.string().describe('Tailscale IP or hostname of the device.'),
            port: z.number().default(5252),
          }),
          async run({ address, port }) {
            const url = `http://${address}:${port}/api/data`
            try {
              const res = await fetch(url, { signal: AbortSignal.timeout(8000) })
              const body = await res.text()
              return {
                reachable: true,
                status: res.status,
                csrfRequired: Boolean(res.headers.get('x-csrf-token')) || res.status === 403,
                looksLikeWebClient: /DeviceName|Profile|ExitNodeStatus/.test(body),
                hint: res.status === 200
                  ? 'web interface is up — exit-node switching from here needs the tailnet policy to grant canEdit: exitNodes on this device\'s tag'
                  : 'reachable but not serving the API — the client may need `tailscale set --webclient`',
              }
            } catch (e) {
              return { reachable: false, error: e.message, hint: 'run `tailscale set --webclient` on that device, and confirm the tailnet policy allows access to port 5252' }
            }
          },
        }),
      ],
    }
  },
})
