#!/usr/bin/env node
// MCP entry point. Nothing may be written to stdout here except the protocol itself, so this file
// stays empty of everything but the connect call — diagnostics go to stderr or nowhere.

import { serveStdio } from '../src/mcp/server.mjs'

try {
  await serveStdio()
} catch (e) {
  process.stderr.write(`argus-mcp: ${e.message}\n`)
  process.exit(1)
}
