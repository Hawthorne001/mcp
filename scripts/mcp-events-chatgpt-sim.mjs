// Plays the ChatGPT side of MCP Events webhook delivery against a real server:
// server/discover → events/list → events/subscribe with a callback URL and a
// whsec_ secret, then receives, verifies and prints deliveries. A cloudflared
// quick tunnel gives the local receiver a public HTTPS URL.
//
//   export CLOUDFLARE_API_TOKEN=...      # or MCP_TOKEN: any bearer /mcp accepts
//   export CLOUDFLARE_ACCOUNT_ID=...
//   export MCP_EVENT_WORKER=my-worker    # optional; omit to watch the account
//   node scripts/mcp-events-chatgpt-sim.mjs
//
// MCP_URL defaults to https://mcp.cloudflare.com/mcp. Ctrl-C unsubscribes and
// closes the tunnel. Set MCP_EVENT_RESPONSE_STATUS=503 to make the receiver
// reject deliveries (to watch retries), or 410 to drop them.

import { spawn } from 'node:child_process'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'

const EVENT = 'cloudflare.alert.workers_observability_real_time_issue'
const PROTOCOL = '2026-07-28'
const endpoint = process.env.MCP_URL ?? 'https://mcp.cloudflare.com/mcp'
const token = process.env.MCP_TOKEN ?? process.env.CLOUDFLARE_API_TOKEN
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID
const worker = process.env.MCP_EVENT_WORKER
const port = Number(process.env.MCP_EVENT_RECEIVER_PORT ?? 8788)
const deliveryStatus = Number(process.env.MCP_EVENT_RESPONSE_STATUS ?? 200)
if (!token) throw new Error('Set CLOUDFLARE_API_TOKEN or MCP_TOKEN')
if (!accountId) throw new Error('Set CLOUDFLARE_ACCOUNT_ID')

const secret = `whsec_${randomBytes(32).toString('base64')}`
const key = Buffer.from(secret.slice(6), 'base64')
const seen = new Set()
const log = (label, value = '') =>
  console.log(
    `${new Date().toISOString().slice(11, 19)} ${label}`,
    typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  )

// --- MCP client (stateless 2026-07-28 requests, like ChatGPT) ---------------
let nextId = 1
async function rpc(method, params = {}) {
  const body = {
    jsonrpc: '2.0',
    id: nextId++,
    method,
    params: {
      ...params,
      _meta: {
        'io.modelcontextprotocol/protocolVersion': PROTOCOL,
        'io.modelcontextprotocol/clientInfo': { name: 'mcp-events-chatgpt-sim', version: '1.0.0' },
        'io.modelcontextprotocol/clientCapabilities': {}
      }
    }
  }
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'MCP-Protocol-Version': PROTOCOL,
      'Mcp-Method': method,
      ...(params.name ? { 'Mcp-Name': params.name } : {})
    },
    body: JSON.stringify(body)
  })
  const text = await response.text()
  const json = response.headers.get('content-type')?.includes('text/event-stream')
    ? text
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => JSON.parse(line.slice(5)))
        .find((message) => message.id === body.id)
    : JSON.parse(text || '{}')
  if (!response.ok || json?.error)
    throw new Error(`${method} failed (${response.status}): ${JSON.stringify(json?.error ?? text)}`)
  return json.result
}

// --- Webhook receiver (what ChatGPT's callback endpoint does) ---------------
function verify(headers, body) {
  const id = headers['webhook-id']
  const timestamp = headers['webhook-timestamp']
  if (!id || !/^\d+$/.test(timestamp ?? '')) return 'missing webhook headers'
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return 'stale timestamp'
  const expected = createHmac('sha256', key).update(`${id}.${timestamp}.${body}`).digest()
  const ok = String(headers['webhook-signature'] ?? '')
    .split(' ')
    .some((signature) => {
      if (!signature.startsWith('v1,')) return false
      const actual = Buffer.from(signature.slice(3), 'base64')
      return actual.length === expected.length && timingSafeEqual(actual, expected)
    })
  return ok ? null : 'bad signature'
}

const server = createServer(async (request, response) => {
  if (request.method === 'GET') return response.writeHead(200).end('ok')
  if (request.method !== 'POST' || request.url !== '/hook') return response.writeHead(404).end()
  const chunks = []
  for await (const chunk of request) chunks.push(chunk)
  const body = Buffer.concat(chunks).toString('utf8')
  const problem = verify(request.headers, body)
  if (problem) {
    log(`✗ rejected delivery: ${problem}`, { headers: request.headers })
    return response.writeHead(401).end()
  }
  const message = JSON.parse(body)
  if (message.type === 'verification') {
    log('✓ verification challenge answered')
    return response
      .writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ challenge: message.challenge }))
  }
  const id = request.headers['webhook-id']
  const duplicate = seen.has(id)
  seen.add(id)
  log(duplicate ? '↺ duplicate delivery (retry)' : '★ EVENT', {
    subscription: request.headers['x-mcp-subscription-id'],
    userAgent: request.headers['user-agent'],
    respondingWith: deliveryStatus,
    event: message
  })
  response.writeHead(deliveryStatus).end()
})

// --- cloudflared quick tunnel -----------------------------------------------
function startTunnel() {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'cloudflared',
      ['tunnel', '--no-autoupdate', '--url', `http://127.0.0.1:${port}`],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    )
    const timer = setTimeout(() => reject(new Error('cloudflared not ready in 45s')), 45_000)
    let url
    let registered = false
    // Wait for both the URL and a registered edge connection. Probing the
    // hostname earlier gets NXDOMAIN, which local resolvers then cache.
    const onData = (chunk) => {
      const text = String(chunk)
      url ??= /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(text)?.[0]
      registered ||= text.includes('Registered tunnel connection')
      if (url && registered) {
        clearTimeout(timer)
        resolve({ child, url })
      }
    }
    child.stdout.on('data', onData)
    child.stderr.on('data', onData)
    child.on('error', reject)
  })
}

async function waitUntilReachable(url) {
  let lastError
  await new Promise((done) => setTimeout(done, 3000))
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(url)
      if (response.ok) return
      lastError = `HTTP ${response.status}`
    } catch (error) {
      lastError = error.cause?.code ?? error.message
    }
    await new Promise((done) => setTimeout(done, 1000))
  }
  throw new Error(`Tunnel ${url} never became reachable: ${lastError}`)
}

// --- Run ----------------------------------------------------------------------
await new Promise((done) => server.listen(port, '127.0.0.1', done))
log(`receiver listening on http://127.0.0.1:${port}/hook`)
const tunnel = await startTunnel()
await waitUntilReachable(tunnel.url)
const callbackUrl = `${tunnel.url}/hook`
log('tunnel ready', callbackUrl)

const discover = await rpc('server/discover')
log('server/discover capabilities.events =', discover.capabilities?.events ?? 'MISSING')
const events = []
let cursor
do {
  const page = await rpc('events/list', cursor ? { cursor } : {})
  events.push(...page.events)
  cursor = page.nextCursor
} while (cursor && events.length === 0)
log(
  'events/list',
  events.map((event) => event.name)
)
if (!events.some((event) => event.name === EVENT))
  throw new Error(`${EVENT} not offered to this token/account`)

const subscribeParams = {
  name: EVENT,
  arguments: { account_id: accountId, afterOccurrences: 1, ...(worker ? { service: worker } : {}) },
  delivery: { mode: 'webhook', url: callbackUrl, secret }
}
let refreshTimer
async function subscribe(label) {
  const result = await rpc('events/subscribe', subscribeParams)
  log(label, result)
  // Like ChatGPT: refresh a little before refreshBefore.
  const delay = Math.max(Date.parse(result.refreshBefore) - Date.now() - 120_000, 30_000)
  refreshTimer = setTimeout(
    () => subscribe('↻ refreshed').catch((error) => log('✗ refresh failed', error.message)),
    delay
  )
}
await subscribe('✓ subscribed')
log(`waiting for issues${worker ? ` on ${worker}` : ''}. Make the Worker throw. Ctrl-C to stop.`)

let stopping = false
async function stop() {
  if (stopping) return
  stopping = true
  clearTimeout(refreshTimer)
  try {
    const { secret: _secret, ...delivery } = subscribeParams.delivery
    await rpc('events/unsubscribe', { ...subscribeParams, delivery })
    log('✓ unsubscribed')
  } catch (error) {
    log('✗ unsubscribe failed', error.message)
  }
  tunnel.child.kill()
  server.close()
  process.exit(0)
}
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
