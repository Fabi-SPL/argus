// The MCP transport. Every capability any driver declares becomes a tool here automatically — adding
// a device to argus.config.json is enough, there is nothing to register by hand.
//
// This file contains no device knowledge and no policy of its own. It is a translation layer over
// registry.invoke(), which is where guards, confirmation and redaction actually happen. If you find
// yourself wanting to add a check here, it belongs in the core instead — otherwise the hub, which
// goes through the same call, would not get it.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

import { loadConfig } from '../core/config.mjs'
import { Registry } from '../core/registry.mjs'
import { posture } from '../core/posture.mjs'
import { ArgusError } from '../core/errors.mjs'

const text = (v) => ({ content: [{ type: 'text', text: typeof v === 'string' ? v : JSON.stringify(v, null, 2) }] })
const errorText = (e) => ({
  isError: true,
  content: [{ type: 'text', text: JSON.stringify(e instanceof ArgusError ? e.toJSON() : { error: 'FAILED', message: e.message }, null, 2) }],
})

const toolName = (deviceId, capName) => `${deviceId}_${capName}`.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64)

const KIND_NOTE = {
  read: 'Read-only.',
  diagnose: 'Read-only probe; may take a few seconds.',
  write: 'CHANGES DEVICE STATE. Runs as a dry run by default; pass confirm: true and dryRun: false to apply.',
  restart: 'RESTARTS THE DEVICE. Requires confirm: true.',
}

export async function createServer(options = {}) {
  const config = loadConfig(options)
  const registry = await Registry.load(config)
  const server = new McpServer({ name: 'argus', version: '0.1.0' })

  server.registerTool('argus_overview', {
    title: 'Network overview',
    description: 'Every device Argus manages, whether it answered just now, and what it reports about itself. Start here.',
    inputSchema: {},
  }, async () => {
    try { return text({ site: config.site, devices: await registry.probeAll() }) }
    catch (e) { return errorText(e) }
  })

  server.registerTool('argus_posture', {
    title: 'Security posture',
    description: 'One verdict on whether the network is exposed right now — gateway, access points and VPN read together. Answers "am I actually protected".',
    inputSchema: {},
  }, async () => {
    try { return text(await posture(registry)) }
    catch (e) { return errorText(e) }
  })

  server.registerTool('argus_capabilities', {
    title: 'List capabilities',
    description: 'Every capability across every device, with its reference and kind. Use with argus_invoke when a capability has no dedicated tool.',
    inputSchema: { kind: z.enum(['read', 'diagnose', 'write', 'restart']).optional() },
  }, async ({ kind }) => {
    try { return text({ devices: registry.listDevices(), capabilities: registry.listCapabilities({ kind }) }) }
    catch (e) { return errorText(e) }
  })

  server.registerTool('argus_invoke', {
    title: 'Invoke a capability by reference',
    description: 'Escape hatch: calls any capability as "<device>.<capability>". Same path, same guards as the dedicated tools.',
    inputSchema: {
      ref: z.string().describe('e.g. "gateway.status" — see argus_capabilities.'),
      args: z.record(z.string(), z.any()).default({}),
      confirm: z.boolean().default(false).describe('Required for capabilities that change device state.'),
    },
  }, async ({ ref, args, confirm }) => {
    try { return text(await registry.invoke(ref, args, { confirm })) }
    catch (e) { return errorText(e) }
  })

  // One tool per capability. The shape comes straight off the driver's zod schema, so a driver
  // author writes the schema once and it surfaces here and in the hub identically.
  for (const device of registry.listDevices()) {
    for (const ref of registry.listCapabilities().filter((c) => c.device === device.id)) {
      const cap = registry.capability(ref.ref)
      const shape = cap.input?.shape ?? {}
      const mutating = cap.kind === 'write' || cap.kind === 'restart'

      server.registerTool(toolName(device.id, cap.name), {
        title: `${device.title}: ${cap.title}`,
        description: `${cap.title} on ${device.title} (${device.vendor ?? device.driver}). ${KIND_NOTE[cap.kind]}`,
        inputSchema: {
          ...shape,
          ...(mutating ? { confirm: z.boolean().default(false).describe('Must be true to apply. Without it the call is refused.') } : {}),
        },
      }, async (args = {}) => {
        const { confirm = false, ...rest } = args
        try { return text(await registry.invoke(ref.ref, rest, { confirm })) }
        catch (e) { return errorText(e) }
      })
    }
  }

  return { server, registry, config }
}

/** Entry point used by bin/argus-mcp.mjs. */
export async function serveStdio(options) {
  const { server, registry } = await createServer(options)
  await server.connect(new StdioServerTransport())
  return registry
}
