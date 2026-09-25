/**
 * Dashboard sign-in flow: with MERIDIAN_API_KEY set, browsers authenticate
 * once at /login and get an HttpOnly cookie; API clients keep the header
 * contract (x-api-key / Authorization: Bearer → JSON 401 on mismatch).
 *
 * The cookie is an HMAC derived from the key, so it can't be replayed as an
 * x-api-key, and rotating the key invalidates every outstanding cookie.
 */
import { describe, it, expect, beforeAll, afterAll } from "bun:test"

const SAVED_KEY = process.env.MERIDIAN_API_KEY
const TEST_KEY = "test-dashboard-login-key"

beforeAll(() => {
  process.env.MERIDIAN_API_KEY = TEST_KEY
})

afterAll(() => {
  if (SAVED_KEY !== undefined) process.env.MERIDIAN_API_KEY = SAVED_KEY
  else delete process.env.MERIDIAN_API_KEY
})

// Imported after env is set — matches the suite-wide pattern for
// env-sensitive imports (see proxy-settings-auth.test.ts).
const { createProxyServer } = await import("../proxy/server")

const loginWith = async (app: { fetch: (r: Request) => Response | Promise<Response> }, key: string, next = "/") => {
  const form = new URLSearchParams({ key, next })
  return await app.fetch(new Request("http://localhost/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  }))
}

const cookieOf = (res: Response): string => {
  const setCookie = res.headers.get("set-cookie") ?? ""
  return setCookie.split(";")[0] ?? ""
}

describe("GET /login", () => {
  it("serves the sign-in form without auth", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/login"))
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('action="/login"')
    expect(html).toContain('name="key"')
  })

  it("redirects home when auth is disabled", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    delete process.env.MERIDIAN_API_KEY
    try {
      const res = await app.fetch(new Request("http://localhost/login"))
      expect(res.status).toBe(302)
      expect(res.headers.get("location")).toBe("/")
    } finally {
      process.env.MERIDIAN_API_KEY = TEST_KEY
    }
  })
})

describe("POST /login", () => {
  it("sets an HttpOnly SameSite cookie and redirects on the right key", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await loginWith(app, TEST_KEY, "/telemetry")
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/telemetry")
    const setCookie = res.headers.get("set-cookie") ?? ""
    expect(setCookie).toContain("meridian_auth=")
    expect(setCookie).toContain("HttpOnly")
    expect(setCookie).toContain("SameSite=Lax")
    // The cookie must be a derived token, never the key itself.
    expect(setCookie).not.toContain(TEST_KEY)
  })

  it("answers 401 with the form and no cookie on a wrong key", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await loginWith(app, "wrong-key")
    expect(res.status).toBe(401)
    expect(res.headers.get("set-cookie")).toBeNull()
    expect(await res.text()).toContain("didn't match")
  })

  it("collapses non-same-origin next targets to / (no open redirect)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    for (const evil of ["//evil.example", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"]) {
      const res = await loginWith(app, TEST_KEY, evil)
      expect(res.status).toBe(302)
      expect(res.headers.get("location"), `next=${evil} must not escape origin`).toBe("/")
    }
  })
})

describe("cookie session", () => {
  it("grants access to gated JSON and HTML routes", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const cookie = cookieOf(await loginWith(app, TEST_KEY))
    expect(cookie).toContain("meridian_auth=")

    const json = await app.fetch(new Request("http://localhost/settings/api/features", {
      headers: { cookie },
    }))
    expect(json.status).toBe(200)

    const html = await app.fetch(new Request("http://localhost/telemetry", {
      headers: { cookie, accept: "text/html" },
    }))
    expect(html.status).toBe(200)
  })

  it("rejects a forged cookie", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/settings/api/features", {
      headers: { cookie: "meridian_auth=deadbeef" },
    }))
    expect(res.status).toBe(401)
  })

  it("is invalidated by rotating MERIDIAN_API_KEY", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const cookie = cookieOf(await loginWith(app, TEST_KEY))
    process.env.MERIDIAN_API_KEY = "rotated-key"
    try {
      const res = await app.fetch(new Request("http://localhost/settings/api/features", {
        headers: { cookie },
      }))
      expect(res.status).toBe(401)
    } finally {
      process.env.MERIDIAN_API_KEY = TEST_KEY
    }
  })

  it("cannot be replayed as an x-api-key", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const cookie = cookieOf(await loginWith(app, TEST_KEY))
    const token = cookie.split("=")[1] ?? ""
    const res = await app.fetch(new Request("http://localhost/settings/api/features", {
      headers: { "x-api-key": token },
    }))
    expect(res.status).toBe(401)
  })
})

describe("browser redirect vs API 401", () => {
  it("redirects an unauthenticated browser page load to /login with next", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/telemetry?window=24h", {
      headers: { accept: "text/html,application/xhtml+xml" },
    }))
    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe(`/login?next=${encodeURIComponent("/telemetry?window=24h")}`)
  })

  it("keeps the JSON 401 for non-HTML requests (audit contract)", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    for (const headers of [{}, { accept: "application/json" }] as Array<Record<string, string>>) {
      const res = await app.fetch(new Request("http://localhost/telemetry", { headers }))
      expect(res.status).toBe(401)
      const body = await res.json() as { error?: { type?: string } }
      expect(body.error?.type).toBe("authentication_error")
    }
  })

  it("keeps the JSON 401 for HTML-accepting non-GET requests", async () => {
    const { app } = createProxyServer({ port: 0, host: "127.0.0.1" })
    const res = await app.fetch(new Request("http://localhost/profiles/active", {
      method: "POST",
      headers: { accept: "text/html", "Content-Type": "application/json" },
      body: "{}",
    }))
    expect(res.status).toBe(401)
  })
})
