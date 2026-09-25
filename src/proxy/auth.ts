/**
 * Optional API key authentication middleware.
 *
 * When MERIDIAN_API_KEY is set, requests to protected routes must include
 * a matching key via `x-api-key` header or `Authorization: Bearer` header,
 * or carry the dashboard session cookie issued by `POST /login`.
 * When unset, all routes are open (default behavior, backward compatible).
 *
 * The cookie value is an HMAC derived from the configured key, not the key
 * itself: a leaked cookie unlocks the dashboard but cannot be replayed as an
 * `x-api-key` by API clients, and rotating MERIDIAN_API_KEY invalidates every
 * outstanding cookie with no server-side session state.
 *
 * Uses constant-time comparison to prevent timing attacks.
 */

import { createHmac, timingSafeEqual } from "node:crypto"
import type { Context, Next } from "hono"

export const AUTH_COOKIE_NAME = "meridian_auth"

/** Cookie lifetime: 7 days, then the browser re-prompts via /login. */
const AUTH_COOKIE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

function getConfiguredKey(): string | undefined {
  return process.env.MERIDIAN_API_KEY || undefined
}

/**
 * Whether API key authentication is enabled.
 * True when MERIDIAN_API_KEY is set to a non-empty value.
 */
export function authEnabled(): boolean {
  return Boolean(getConfiguredKey())
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Hashes both values to ensure equal-length comparison regardless of input.
 */
function safeCompare(a: string, b: string): boolean {
  const hashA = createHmac("sha256", "meridian").update(a).digest()
  const hashB = createHmac("sha256", "meridian").update(b).digest()
  return timingSafeEqual(hashA, hashB)
}

/** The dashboard cookie value for the currently configured key. */
function dashboardCookieValue(key: string): string {
  return createHmac("sha256", key).update("meridian-dashboard-cookie-v1").digest("hex")
}

/** Verify a caller-supplied key (login form) against the configured key. */
export function verifyApiKey(provided: string): boolean {
  const key = getConfiguredKey()
  return Boolean(key && provided && safeCompare(provided, key))
}

/**
 * Build the `Set-Cookie` header value for a successful dashboard login.
 * `secure` should reflect whether the caller reached us over HTTPS
 * (directly or via a terminating proxy) — plain-HTTP localhost use must
 * keep working, so the flag is per-request rather than unconditional.
 */
export function buildAuthCookie(secure: boolean): string {
  const key = getConfiguredKey()
  if (!key) throw new Error("buildAuthCookie requires MERIDIAN_API_KEY to be set")
  const attributes = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${AUTH_COOKIE_MAX_AGE_SECONDS}`
  return `${AUTH_COOKIE_NAME}=${dashboardCookieValue(key)}; ${attributes}${secure ? "; Secure" : ""}`
}

/** Extract the dashboard cookie from a Cookie header, if present. */
function cookieFromHeader(cookieHeader: string | null | undefined): string | undefined {
  if (!cookieHeader) return undefined
  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim()
    if (trimmed.startsWith(`${AUTH_COOKIE_NAME}=`)) return trimmed.slice(AUTH_COOKIE_NAME.length + 1)
  }
  return undefined
}

/** Whether the request carries a valid dashboard session cookie. */
export function hasValidAuthCookie(headers: Headers): boolean {
  const key = getConfiguredKey()
  if (!key) return true
  const cookie = cookieFromHeader(headers.get("cookie"))
  return Boolean(cookie && safeCompare(cookie, dashboardCookieValue(key)))
}

/** Shared by the Hono default backend and standard-Request runtime backends. */
export function hasValidApiKey(headers: Headers): boolean {
  const key = getConfiguredKey()
  if (!key) return true
  const authorization = headers.get("authorization")
  const provided = headers.get("x-api-key") || (authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined)
  if (provided && safeCompare(provided, key)) return true
  return hasValidAuthCookie(headers)
}

/**
 * Extract the API key from the request.
 * Checks x-api-key header first, then Authorization: Bearer.
 */
function extractKey(c: Context): string | undefined {
  const apiKey = c.req.header("x-api-key")
  if (apiKey) return apiKey

  const auth = c.req.header("authorization")
  if (auth?.startsWith("Bearer ")) return auth.slice(7)

  return undefined
}

/**
 * Hono middleware that rejects requests without a valid API key or
 * dashboard cookie. No-op when MERIDIAN_API_KEY is not set.
 *
 * Browser page loads (GET with `Accept: text/html`) are redirected to
 * /login instead of receiving the JSON 401, so the web dashboard stays
 * usable when auth is on. API clients — including the security audit in
 * proxy-settings-auth.test.ts, which probes without an HTML Accept
 * header — keep the exact 401 JSON contract.
 */
export async function requireAuth(c: Context, next: Next) {
  const key = getConfiguredKey()
  if (!key) return next()

  const provided = extractKey(c)
  if (provided && safeCompare(provided, key)) return next()
  if (hasValidAuthCookie(c.req.raw.headers)) return next()

  if (c.req.method === "GET" && (c.req.header("accept") ?? "").includes("text/html")) {
    const url = new URL(c.req.url)
    return c.redirect(`/login?next=${encodeURIComponent(url.pathname + url.search)}`, 302)
  }

  return c.json({
    type: "error",
    error: {
      type: "authentication_error",
      message: "Invalid or missing API key",
    },
  }, 401)
}
