// Microsoft Entra ID (company SSO) gate for the Field Survey Dashboard.
//
// Runs at Netlify's edge on every request, before any file is served.
//
//   * No valid session  -> redirect to Microsoft sign-in (OpenID Connect authorization-code flow + PKCE).
//   * Sign-in callback  -> ID token verified against the tenant's signing keys; the user is authorized by
//                          tenant id + object id (and, if configured, security-group membership).
//   * Valid session     -> the page is served. Sessions are short, renew only while active, have a hard
//                          lifetime cap and can be revoked server-side.
//   * Sign-out          -> same-site POST carrying a short-lived CSRF token bound to the session; the session id is written to a
//                          revocation store that every request consults.
//   * Any error         -> the request is refused (the function fails closed; see `onError` below).
//
// Every redirect target is built from configuration (SITE_URL / the tenant), never from the request.
//
// Environment variables (Netlify > Site configuration > Environment variables):
//   ENTRA_TENANT_ID      directory (tenant) ID
//   ENTRA_CLIENT_ID      application (client) ID
//   ENTRA_CLIENT_SECRET  client secret value
//   SESSION_SECRET       random string, 32+ characters, signs the session cookie
//   SITE_URL             canonical address of the site, e.g. https://mbrewfielddashboard.netlify.app
//                        (optional: defaults to the site's primary Netlify URL)
//   ENTRA_GROUP_ID       optional: object ID of a security group; only its members are let in
//   ALLOWED_DOMAIN       optional: sign-in name must end with this domain (default monsterbrewing.com)
//   SESSION_HOURS        optional: hard session lifetime, 1-12 hours (default 8)
//   IDLE_MINUTES         optional: inactivity timeout, 5-120 minutes (default 60)

import type { Config, Context } from "https://edge.netlify.com/v1/index.ts";
import { createRemoteJWKSet, jwtVerify, SignJWT } from "npm:jose@5.9.6";
import { getStore } from "npm:@netlify/blobs@11.1.7";

// ------------------------------------------------------------------ configuration
const env = (k: string, d = "") => Netlify.env.get(k) ?? d;
const clamp = (v: string, def: number, min: number, max: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.min(max, Math.max(min, n)) : def;
};

const TENANT = env("ENTRA_TENANT_ID");
const CLIENT_ID = env("ENTRA_CLIENT_ID");
const CLIENT_SECRET = env("ENTRA_CLIENT_SECRET");
const SESSION_SECRET = env("SESSION_SECRET");
const GROUP_ID = env("ENTRA_GROUP_ID");
const DOMAIN = env("ALLOWED_DOMAIN", "monsterbrewing.com").toLowerCase();
const SESSION_HOURS = clamp(env("SESSION_HOURS"), 8, 1, 12);
const IDLE_MINUTES = clamp(env("IDLE_MINUTES"), 60, 5, 120);

const MS = "https://login.microsoftonline.com";
const ISSUER = `${MS}/${TENANT}/v2.0`;
const AUTHORIZE_URL = `${MS}/${TENANT}/oauth2/v2.0/authorize`;
const TOKEN_URL = `${MS}/${TENANT}/oauth2/v2.0/token`;
const MS_LOGOUT_URL = `${MS}/${TENANT}/oauth2/v2.0/logout`;
const JWKS = createRemoteJWKSet(new URL(`${MS}/${TENANT}/discovery/v2.0/keys`));

const SESSION_COOKIE = "__Host-fsd_session";
const FLOW_COOKIE = "__Host-fsd_flow";
const SESSION_AUD = "field-survey-dashboard";
const HOME_PATH = "/";
const CALLBACK_PATH = "/.auth/callback";
const LOGOUT_PATH = "/.auth/logout";

// ------------------------------------------------------------------ small helpers
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randomString = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s: string) =>
  b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
const secretKey = () => new TextEncoder().encode(SESSION_SECRET);
const nowSec = () => Math.floor(Date.now() / 1000);

/** The one origin this site answers on. Taken from configuration, never from the request's Host header. */
function canonicalOrigin(context: Context): string | null {
  const configured = env("SITE_URL") || context.site?.url || "";
  try {
    const u = new URL(configured);
    return u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}

function cookie(name: string, value: string, maxAgeSec: number) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}
function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

/** Redirect to a fixed, configuration-derived location. `location` is never taken from user input. */
function redirectTo(location: string, cookies: string[] = []) {
  const h = new Headers({ ...SECURITY_HEADERS, Location: location });
  cookies.forEach((c) => h.append("Set-Cookie", c));
  return new Response(null, { status: 302, headers: h });
}

/** Static HTML page. `message` and `extraHtml` are always literals from this file, never request data. */
function page(title: string, message: string, status: number, extraHtml = "", cookies: string[] = []) {
  const h = new Headers({ ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" });
  cookies.forEach((c) => h.append("Set-Cookie", c));
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>${title}</title>
<body style="font-family:system-ui;background:#131512;color:#ECEFE6;padding:40px">
<h1 style="color:#92D400">Field Survey Dashboard</h1><p>${message}</p>${extraHtml}</body>`,
    { status, headers: h },
  );
}
const RETRY_LINK = `<p><a style="color:#92D400" href="${HOME_PATH}">Try again</a></p>`;
const deny = (message: string, status = 403, cookies: string[] = []) => page("Access denied", message, status, RETRY_LINK, cookies);

// ------------------------------------------------------------------ revocation store (fails closed)
class StoreUnavailable extends Error {}
const revokedStore = () => getStore({ name: "revoked-sessions", consistency: "strong" });

/** True if this session id was signed out. Throws StoreUnavailable when the answer is unknown,
 *  and the caller then refuses the request: an outage never grants access. */
async function isRevoked(jti: string): Promise<boolean> {
  try {
    return (await revokedStore().get(jti)) !== null;
  } catch (e) {
    console.error("revocation store unavailable:", e);
    throw new StoreUnavailable();
  }
}
async function revoke(jti: string, login: number): Promise<void> {
  try {
    await revokedStore().setJSON(jti, { revokedAt: Date.now(), validUntil: (login + SESSION_HOURS * 3600) * 1000 });
  } catch (e) {
    console.error("could not record sign-out:", e);
    throw new StoreUnavailable();
  }
}

// ------------------------------------------------------------------ sessions
type Session = { oid: string; tid: string; email: string; name: string; jti: string; login: number; iat: number };

/** Expires at the idle timeout, but never later than the hard lifetime measured from the original sign-in. */
async function mintSession(s: Omit<Session, "iat">, origin: string): Promise<{ token: string; maxAge: number }> {
  const now = nowSec();
  const exp = Math.min(now + IDLE_MINUTES * 60, s.login + SESSION_HOURS * 3600);
  const token = await new SignJWT({ tid: s.tid, email: s.email, name: s.name, login: s.login })
    .setProtectedHeader({ alg: "HS256" }).setSubject(s.oid).setJti(s.jti).setIssuer(origin).setAudience(SESSION_AUD)
    .setIssuedAt(now).setExpirationTime(exp).sign(secretKey());
  return { token, maxAge: Math.max(0, exp - now) };
}

/** Returns the session only if every check passes; otherwise null (signed out).
 *  Signature (HS256 only), issuer, audience, expiry, idle age, hard lifetime, tenant, user id and
 *  sign-in domain are all required. Revocation is checked by the caller. */
async function readSession(token: string | undefined, origin: string): Promise<Session | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secretKey(), {
      algorithms: ["HS256"], issuer: origin, audience: SESSION_AUD, maxTokenAge: `${IDLE_MINUTES}m`,
    });
    const now = nowSec();
    const oid = typeof payload.sub === "string" ? payload.sub : "";
    const tid = typeof payload.tid === "string" ? payload.tid : "";
    const email = typeof payload.email === "string" ? payload.email.toLowerCase() : "";
    const login = typeof payload.login === "number" ? payload.login : 0;
    const jti = typeof payload.jti === "string" ? payload.jti : "";
    const iat = typeof payload.iat === "number" ? payload.iat : 0;
    if (!oid || !jti || !iat || !login) return null;
    if (tid !== TENANT) return null;
    if (!email.endsWith("@" + DOMAIN)) return null;
    if (now >= login + SESSION_HOURS * 3600) return null;
    return { oid, tid, email, name: String(payload.name || ""), jti, login, iat };
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ CSRF protection
/** State-changing requests must be sent by this site: the browser's Origin (or Referer) has to match. */
function sameOrigin(req: Request, origin: string): boolean {
  const o = req.headers.get("origin");
  if (o !== null) return o === origin;
  const r = req.headers.get("referer");
  if (r === null) return false;
  try {
    return new URL(r).origin === origin;
  } catch {
    return false;
  }
}
/** Short-lived form token bound to the signed-in session; required (with sameOrigin) to sign out.
 *  It dies with the session, so it cannot be replayed after the sign-out succeeds. */
async function csrfToken(sess: Session, origin: string): Promise<string> {
  return await new SignJWT({ purpose: "logout", sid: sess.jti })
    .setProtectedHeader({ alg: "HS256" }).setIssuer(origin).setAudience(SESSION_AUD)
    .setIssuedAt().setExpirationTime("10m").sign(secretKey());
}
async function csrfValid(token: string, sess: Session, origin: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, secretKey(), {
      algorithms: ["HS256"], issuer: origin, audience: SESSION_AUD, maxTokenAge: "10m",
    });
    return payload.purpose === "logout" && payload.sid === sess.jti;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------------ sign-in
async function startLogin(origin: string) {
  const state = randomString(16);
  const nonce = randomString(16);
  const verifier = randomString(48);
  const flow = await new SignJWT({ state, nonce, verifier })
    .setProtectedHeader({ alg: "HS256" }).setIssuer(origin).setAudience(SESSION_AUD)
    .setIssuedAt().setExpirationTime("10m").sign(secretKey());
  const p = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: origin + CALLBACK_PATH,
    response_mode: "query",
    scope: "openid profile email",
    state,
    nonce,
    code_challenge: await sha256(verifier),
    code_challenge_method: "S256",
    prompt: "select_account",
  });
  // Also drop any stale session cookie.
  return redirectTo(`${AUTHORIZE_URL}?${p}`, [cookie(FLOW_COOKIE, flow, 600), cookie(SESSION_COOKIE, "", 0)]);
}

async function finishLogin(req: Request, url: URL, origin: string) {
  const clearFlow = [cookie(FLOW_COOKIE, "", 0)];
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const flowCookie = readCookie(req, FLOW_COOKIE);
  if (!code || !state || !flowCookie) return deny("Sign-in did not complete. Please try again.", 400, clearFlow);

  let flow: Record<string, unknown>;
  try {
    flow = (await jwtVerify(flowCookie, secretKey(), {
      algorithms: ["HS256"], issuer: origin, audience: SESSION_AUD, maxTokenAge: "10m",
    })).payload;
  } catch {
    return deny("Sign-in expired. Please try again.", 400, clearFlow);
  }
  if (typeof flow.state !== "string" || flow.state !== state || typeof flow.verifier !== "string" || typeof flow.nonce !== "string") {
    return deny("Sign-in could not be validated. Please try again.", 400, clearFlow);
  }

  const tr = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: origin + CALLBACK_PATH,
      code_verifier: flow.verifier,
    }),
  });
  if (!tr.ok) return deny("Microsoft rejected the sign-in. Please try again.", 401, clearFlow);
  const tokens = await tr.json();

  let claims: Record<string, unknown>;
  try {
    claims = (await jwtVerify(String(tokens.id_token || ""), JWKS, {
      issuer: ISSUER, audience: CLIENT_ID, algorithms: ["RS256"], maxTokenAge: "10m", clockTolerance: 60,
    })).payload;
  } catch {
    return deny("The sign-in token could not be verified.", 401, clearFlow);
  }

  // ---- authorization: who is allowed in ----
  // Identity is the immutable tenant id + object id from the verified token (not the email address).
  const tid = typeof claims.tid === "string" ? claims.tid : "";
  const oid = typeof claims.oid === "string" ? claims.oid : "";
  if (claims.nonce !== flow.nonce) return deny("The sign-in response did not match the request.", 401, clearFlow);
  if (tid !== TENANT || !oid) return deny("This account is not part of the company directory.", 403, clearFlow);
  const email = String(claims.preferred_username || claims.email || "").toLowerCase();
  if (!email.endsWith("@" + DOMAIN)) return deny("Only company accounts can view this dashboard.", 403, clearFlow);
  if (GROUP_ID) {
    // Membership must be asserted in the token. A missing or truncated ("overage") groups claim is a refusal.
    const groups = Array.isArray(claims.groups) ? claims.groups.filter((g): g is string => typeof g === "string") : null;
    if (!groups || !groups.includes(GROUP_ID)) {
      return deny("Your account is not in the dashboard access group. Ask IT to add you.", 403, clearFlow);
    }
  }

  const { token, maxAge } = await mintSession(
    { oid, tid, email, name: String(claims.name || ""), jti: randomString(16), login: nowSec() }, origin);
  return redirectTo(origin + HOME_PATH, [cookie(SESSION_COOKIE, token, maxAge), ...clearFlow]);
}

// ------------------------------------------------------------------ sign-out
async function logoutPage(sess: Session | null, origin: string) {
  if (!sess) {
    return page("Signed out", "You are signed out.", 200, `<p><a style="color:#92D400" href="${HOME_PATH}">Sign in</a></p>`);
  }
  const token = await csrfToken(sess, origin); // base64url characters only
  return page("Sign out", "Sign out of the Field Survey Dashboard?", 200,
    `<form method="post" action="${LOGOUT_PATH}"><input type="hidden" name="csrf" value="${token}">
<button style="background:#92D400;border:0;border-radius:4px;padding:10px 22px;font-weight:700;cursor:pointer" type="submit">Sign out</button></form>
<p><a style="color:#92D400" href="${HOME_PATH}">Back to the dashboard</a></p>`);
}

async function doLogout(req: Request, sess: Session | null, origin: string) {
  const clear = [cookie(SESSION_COOKIE, "", 0)];
  if (sess) {
    let token = "";
    try {
      token = String((await req.formData()).get("csrf") || "");
    } catch { /* no form body: treated as a missing token below */ }
    if (!(await csrfValid(token, sess, origin))) return page("Sign out", "That sign-out request was not valid.", 403, RETRY_LINK);
    await revoke(sess.jti, sess.login); // throws StoreUnavailable -> handler answers 503 and keeps the cookie
  }
  const back = encodeURIComponent(origin + HOME_PATH);
  return redirectTo(`${MS_LOGOUT_URL}?post_logout_redirect_uri=${back}`, clear);
}

// ------------------------------------------------------------------ request handler
export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  const origin = canonicalOrigin(context);
  if (!origin || !TENANT || !CLIENT_ID || !CLIENT_SECRET || SESSION_SECRET.length < 32) {
    return page("Unavailable", "Sign-in is not configured yet.", 503);
  }
  // Only the canonical address is served (also blocks Host-header tricks and preview URLs).
  if (url.origin !== origin) return redirectTo(origin + HOME_PATH);

  const isRead = req.method === "GET" || req.method === "HEAD";
  if (!isRead && req.method !== "POST") return new Response("Method not allowed", { status: 405, headers: SECURITY_HEADERS });
  if (!isRead && !sameOrigin(req, origin)) return new Response("Cross-site request blocked", { status: 403, headers: SECURITY_HEADERS });

  try {
    if (url.pathname === CALLBACK_PATH) {
      return isRead ? await finishLogin(req, url, origin) : new Response("Method not allowed", { status: 405, headers: SECURITY_HEADERS });
    }

    // Authenticate: valid signature and claims, and not signed out.
    const candidate = await readSession(readCookie(req, SESSION_COOKIE), origin);
    const sess = candidate && !(await isRevoked(candidate.jti)) ? candidate : null;

    if (url.pathname === LOGOUT_PATH) {
      return req.method === "POST" ? await doLogout(req, sess, origin) : await logoutPage(sess, origin);
    }

    if (!sess) {
      if (!isRead) return new Response("Sign in required", { status: 401, headers: SECURITY_HEADERS });
      return await startLogin(origin);
    }

    // Authorized: serve the page, never cached, and renew the cookie once half the idle window has passed.
    const res = await context.next();
    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
    out.headers.set("Cache-Control", "private, no-store");
    if (nowSec() - sess.iat > (IDLE_MINUTES * 60) / 2) {
      const { token, maxAge } = await mintSession(sess, origin);
      if (maxAge > 0) out.headers.append("Set-Cookie", cookie(SESSION_COOKIE, token, maxAge));
    }
    return out;
  } catch (e) {
    // Fail closed: nothing is served when a check could not be completed.
    if (!(e instanceof StoreUnavailable)) console.error("auth error:", e);
    return page("Unavailable", "The sign-in service is temporarily unavailable. Please try again in a minute.", 503);
  }
};

// onError "fail": if this function ever crashes, Netlify returns an error page instead of bypassing the check.
export const config: Config = { path: "/*", onError: "fail" };
