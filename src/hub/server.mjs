// The hub's HTTP layer. Deliberately boring: four GETs, one POST, and a static file handler.
//
// Every route is a one-line wrapper over the same registry the MCP server uses, which is the rule
// Argus is built around — the browser cannot reach a device except through registry.invoke(), so the
// UI has no capability an agent lacks, and no agent has a capability the UI cannot show. There is no
// second code path to keep in sync because there is no second code path.
//
// Binds to loopback by default. This thing holds admin credentials for every router in the house; if
// you move it off 127.0.0.1, put it behind something that authenticates.

import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { loadConfig } from '../core/config.mjs'
import { Registry } from '../core/registry.mjs'
import { posture } from '../core/posture.mjs'
import { ArgusError } from '../core/errors.mjs'

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public')

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' }

const send = (res, status, body, type = 'application/json') => {
  const payload = type.startsWith('application/json') ? JSON.stringify(body, null, 2) : body
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' })
  res.end(payload)
}

function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (c) => {
      raw += c
      if (raw.length > limit) { reject(new Error('body too large')); req.destroy() }
    })
    req.on('end', () => {
      if (!raw) return resolve({})
      try { resolve(JSON.parse(raw)) } catch { reject(new Error('body is not valid JSON')) }
    })
    req.on('error', reject)
  })
}

function serveStatic(res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '')
  const file = path.join(PUBLIC, rel)
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    return send(res, 404, { error: 'NOT_FOUND', message: urlPath })
  }
  send(res, 200, fs.readFileSync(file), MIME[path.extname(file)] ?? 'application/octet-stream')
}

export async function createHub(options = {}) {
  const config = loadConfig(options)
  const registry = await Registry.load(config)

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost')
    const route = `${req.method} ${url.pathname}`

    try {
      switch (route) {
        case 'GET /api/site':
          return send(res, 200, { site: config.site, policy: config.policy })
        case 'GET /api/devices':
          return send(res, 200, registry.listDevices())
        case 'GET /api/capabilities':
          return send(res, 200, registry.listCapabilities({ kind: url.searchParams.get('kind') ?? undefined }))
        case 'GET /api/overview':
          return send(res, 200, await registry.probeAll())
        case 'GET /api/posture':
          return send(res, 200, await posture(registry))
        case 'POST /api/invoke': {
          const { ref, args = {}, confirm = false } = await readBody(req)
          if (!ref) return send(res, 400, { error: 'INPUT_INVALID', message: 'ref is required' })
          return send(res, 200, await registry.invoke(ref, args, { confirm }))
        }
        default:
          if (req.method === 'GET') return serveStatic(res, url.pathname)
          return send(res, 405, { error: 'METHOD_NOT_ALLOWED', message: route })
      }
    } catch (e) {
      if (e instanceof ArgusError) return send(res, e.httpStatus, e.toJSON())
      return send(res, 500, { error: 'FAILED', message: e.message })
    }
  })

  return { server, registry, config }
}

export async function serveHub(options = {}) {
  const { server, config } = await createHub(options)
  const { hubBind, hubPort } = config.policy
  await new Promise((resolve) => server.listen(hubPort, hubBind, resolve))
  return { server, url: `http://${hubBind}:${hubPort}`, config }
}
