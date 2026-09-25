/**
 * Dashboard sign-in page, served at GET /login when MERIDIAN_API_KEY is set.
 *
 * Deliberately does NOT embed the shared header from profileBar.ts: the
 * header's own fetches (/profiles/list) require auth, which is exactly what
 * the visitor does not have yet. The page must render with zero gated
 * dependencies. For the same reason it gets no nav link — it is reached by
 * redirect, not by navigation.
 *
 * The `next` value is sanitized server-side (same-origin path only) before
 * it is interpolated here.
 */

import { meridianLogoSvg, themeCss } from "./profileBar"

const escapeHtml = (value: string): string =>
  value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")

export function loginPageHtml(options: { next: string; error?: boolean }): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Meridian</title>
<style>
  ${themeCss}
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         color: var(--text); line-height: 1.6; min-height: 100vh;
         display: flex; align-items: center; justify-content: center; }
  .login-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 28px; width: 100%; max-width: 360px; margin: 24px; }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; }
  .brand .mh-logo { width: 28px; height: 28px; }
  .brand span { font-size: 17px; font-weight: 700; }
  h1 { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
  .sub { font-size: 13px; color: var(--muted); margin-bottom: 18px; }
  label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px;
    color: var(--muted); font-weight: 600; margin-bottom: 6px; }
  input[type=password] { width: 100%; background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 14px; }
  input[type=password]:focus { outline: none; border-color: var(--accent); }
  button { margin-top: 14px; width: 100%; background: var(--surface2); color: var(--accent);
    border: 1px solid var(--accent); border-radius: 6px; padding: 8px 10px; font-size: 14px;
    font-weight: 600; cursor: pointer; }
  button:hover { background: color-mix(in srgb, var(--accent) 12%, transparent); }
  .error { font-size: 13px; color: var(--red); margin-bottom: 14px; }
  code { font-family: 'SF Mono', SFMono-Regular, Consolas, monospace; font-size: 12px;
    background: var(--surface2); border: 1px solid var(--border); border-radius: 5px;
    padding: 1px 5px; color: var(--accent2); }
</style>
</head>
<body>
  <main class="login-card">
    <div class="brand">${meridianLogoSvg}<span>Meridian</span></div>
    <h1>Sign in</h1>
    <p class="sub">This instance is protected. Enter the configured <code>MERIDIAN_API_KEY</code> to open the dashboard.</p>
    ${options.error ? `<p class="error">That key didn't match. Check MERIDIAN_API_KEY and try again.</p>` : ""}
    <form method="post" action="/login">
      <input type="hidden" name="next" value="${escapeHtml(options.next)}">
      <label for="key">API key</label>
      <input id="key" name="key" type="password" autocomplete="current-password" autofocus required>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>`
}
