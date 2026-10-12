import { EventApi, EventApiError, POLICIES, AUTOMATIONS } from './api'
import { constantTimeEqual, forwardAnsWebhook } from './ans-bridge'
import { ManagedPolicy, asSubscription, publicWebhookFetch, readPolicyState } from './service'
import {
  deliveryAccessToken,
  ingressSecret,
  readDeliveryTicket,
  type DeliveryTicket,
  type EventEnvironment
} from './state'

/**
 * Why a callback from ANS was acknowledged, dropped or bounced. Logged once
 * per callback with safe fields only, so silent 204s can be told apart.
 */
type CallbackOutcome =
  | 'no_ticket'
  | 'ticket_expired'
  | 'credential_unavailable'
  | 'access_denied'
  | 'account_mismatch'
  | 'forwarded'
  | 'upstream_error'

function logOutcome(
  subscription: string,
  outcome: CallbackOutcome,
  status: number,
  detail: Record<string, unknown> = {}
): void {
  console.log(
    JSON.stringify({ event: 'mcp_events_callback', subscription, outcome, status, ...detail })
  )
}

/**
 * Receive an ANS webhook for one subscription, re-check access and forward it
 * to the subscriber as a signed MCP event.
 */
export async function handleAnsCallback(
  request: Request,
  env: EventEnvironment
): Promise<Response> {
  const deadline = AbortSignal.timeout(4000)
  if (request.method !== 'POST') return new Response(null, { status: 405 })
  const match = /^\/events\/ans\/(sub_[a-f0-9]{64})$/.exec(new URL(request.url).pathname)
  if (!match) return new Response(null, { status: 404 })
  const id = match[1]
  const secret = await ingressSecret(env, id)
  if (!(await constantTimeEqual(request.headers.get('cf-webhook-auth') ?? '', secret)))
    return new Response(null, { status: 401 })
  let ticket: DeliveryTicket | null
  try {
    ticket = await readDeliveryTicket(env, id)
  } catch {
    // Unreadable (e.g. the encryption key rotated): fail closed, don't retry.
    return new Response(null, { status: 401 })
  }
  // No ticket: ANS's creation probe, or the subscription expired or ended.
  if (!ticket) {
    logOutcome(id, 'no_ticket', 204)
    return new Response(null, { status: 204 })
  }
  if (ticket.expiresAt <= Date.now()) {
    logOutcome(id, 'ticket_expired', 204, { expiredAt: new Date(ticket.expiresAt).toISOString() })
    return new Response(null, { status: 204 })
  }
  try {
    const accessToken = await deliveryAccessToken(env, ticket)
    if (!accessToken) {
      logOutcome(id, 'credential_unavailable', 204, { providerIssued: ticket.providerIssued })
      return new Response(null, { status: 204 })
    }
    const api = new EventApi(env.CLOUDFLARE_API_BASE, accessToken, ticket.accountId, deadline)
    const [policyData] = await Promise.all([
      api.result(`${POLICIES}/${encodeURIComponent(ticket.policyId)}`),
      api.result(AUTOMATIONS)
    ])
    const policy = ManagedPolicy.parse(policyData)
    const state = await readPolicyState(env, policy, id)
    if (state.params.arguments.account_id !== ticket.accountId) {
      logOutcome(id, 'account_mismatch', 403)
      return new Response(null, { status: 403 })
    }
    const subscription = asSubscription(state, policy, secret)
    const response = await forwardAnsWebhook(request, id, {
      loadSubscription: async () => subscription,
      hasAccess: async () => true,
      eventIdentity: async (_subscription, payload) => payload.alert_correlation_id ?? '',
      now: Date.now,
      webhookFetch: (input, init) => publicWebhookFetch(input, { ...init, signal: deadline }),
      deactivateSubscription: async () => {
        const { id: _policyId, ...body } = policy
        await api.result(`${POLICIES}/${encodeURIComponent(policy.id)}`, 'PUT', {
          ...body,
          enabled: false
        })
      }
    })
    logOutcome(id, 'forwarded', response.status, {
      active: subscription.active,
      expiresAt: new Date(subscription.expiresAt).toISOString()
    })
    return response
  } catch (error) {
    if (error instanceof EventApiError && [401, 403, 404].includes(error.status)) {
      logOutcome(id, 'access_denied', 204, { upstreamStatus: error.status })
      return new Response(null, { status: 204 })
    }
    logOutcome(id, 'upstream_error', 503, {
      error: error instanceof Error ? error.name : 'unknown'
    })
    return new Response(null, { status: 503 })
  }
}
