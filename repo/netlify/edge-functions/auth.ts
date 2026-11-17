// Microsoft Entra ID (company SSO) gate for the Field Survey Dashboard.
//
// Runs at Netlify's edge on every request before any file is served. A visitor
// without a valid session cookie is redirected to the Microsoft sign-in page
// (OpenID Connect authorization-code flow with PKCE). After sign-in the ID token
// is verified against the tenant's signing keys and a short-lived, HMAC-signed
// session cookie is issued. Nothing about the login lives in the page itself.
//
// Environment variables (Netlify site settings > Environment variables):
//   ENTRA_TENANT_ID      directory (tenant) ID from the app registration
//   ENTRA_CLIENT_ID      application (client) ID
//   ENTRA_CLIENT_SECRET  client secret value (not the secret ID)
//   SESSION_SECRET       random string, 32+ chars, used to sign the session cookie
//   ENTRA_GROUP_ID       optional: object ID of an Entra group; only members get in
//   ALLOWED_DOMAIN       optional: email domain to allow (default monsterbrewing.com)
//   SESSION_HOURS        optional: absolute session lifetime in hours (default 8)
//   IDLE_MINUTES         optional: sign in again after this long without activity (default 60)
//
// Sessions are revocable: /.auth/logout records the session id in a Netlify Blobs store
// ("revoked-sessions") and every request checks it, so a signed-out cookie is dead immediately
// even though it has not reached its expiry time.

import type { Config, Context } from "https://edge.netlify.com/v1/index.ts";
import { createRemoteJWKSet, jwtVerify, SignJWT } from "npm:jose@5.9.6";
import { getStore } from "npm:@netlify/blobs@11.1.7";

const env = (k: string, d = "") => Netlify.env.get(k) ?? d;
const TENANT = env("ENTRA_TENANT_ID");
const CLIENT_ID = env("ENTRA_CLIENT_ID");
const CLIENT_SECRET = env("ENTRA_CLIENT_SECRET");
const SESSION_SECRET = env("SESSION_SECRET");
const GROUP_ID = env("ENTRA_GROUP_ID");
const DOMAIN = env("ALLOWED_DOMAIN", "monsterbrewing.com").toLowerCase();
const SESSION_HOURS = Number(env("SESSION_HOURS", "8")) || 8;
const IDLE_MINUTES = Number(env("IDLE_MINUTES", "60")) || 60;

const ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;
const AUTHZ = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`;
const TOKEN = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
const LOGOUT = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/logout`;
const JWKS = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`));

const SESSION_COOKIE = "fsd_session";
const SESSION_AUD = "field-survey-dashboard";
const REVOKED = () => getStore({ name: "revoked-sessions", consistency: "strong" });
const FLOW_COOKIE = "fsd_flow";
const CALLBACK_PATH = "/.auth/callback";
const LOGOUT_PATH = "/.auth/logout";

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randomString = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s: string) => b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
const secretKey = () => new TextEncoder().encode(SESSION_SECRET);

function cookie(name: string, value: string, maxAgeSec: number) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}
function readCookie(req: Request, name: string): string | undefined {
  const m = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : undefined;
}
function redirect(location: string, cookies: string[] = []) {
  const h = new Headers({ Location: location, "Cache-Control": "no-store" });
  cookies.forEach((c) => h.append("Set-Cookie", c));
  return new Response(null, { status: 302, headers: h });
}
function deny(msg: string, status = 403) {
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>Access denied</title>
<body style="font-family:system-ui;background:#131512;color:#ECEFE6;padding:40px">
<h1 style="color:#92D400">Field Survey Dashboard</h1><p>${msg}</p>
<p><a style="color:#92D400" href="${LOGOUT_PATH}">Sign in with a different account</a></p></body>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } },
  );
}

/** Only an absolute path on this site is accepted as a post-login destination (CWE-601). */
function safeReturnPath(candidate: unknown, origin: string): string {
  if (typeof candidate !== "string" || !candidate.startsWith("/") || candidate.startsWith("//") || candidate.includes("\\")) return "/";
  try {
    const u = new URL(candidate, origin);
    return u.origin === origin ? u.pathname + u.search : "/";
  } catch {
    return "/";
  }
}

async function startLogin(url: URL) {
  const state = randomString(16);
  const verifier = randomString(48);
  const challenge = await sha256(verifier);
  const returnTo = url.pathname + url.search;
  const flow = await new SignJWT({ state, verifier, returnTo })
    .setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("10m").sign(secretKey());
  const p = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: url.origin + CALLBACK_PATH,
    response_mode: "query",
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });
  return redirect(`${AUTHZ}?${p}`, [cookie(FLOW_COOKIE, flow, 600)]);
}

async function finishLogin(req: Request, url: URL) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const flowCookie = readCookie(req, FLOW_COOKIE);
  if (!code || !state || !flowCookie) return deny("Sign-in did not complete. Please try again.", 400);
  let flow: { state?: string; verifier?: string; returnTo?: string };
  try {
    flow = (await jwtVerify(flowCookie, secretKey(), { algorithms: ["HS256"], maxTokenAge: "10m" })).payload as typeof flow;
  } catch {
    return deny("Sign-in expired. Please try again.", 400);
  }
  if (flow.state !== state) return deny("Sign-in state mismatch. Please try again.", 400);

  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: url.origin + CALLBACK_PATH,
    code_verifier: flow.verifier || "",
  });
  const tr = await fetch(TOKEN, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
  if (!tr.ok) return deny("Microsoft rejected the sign-in. Please try again.", 401);
  const tokens = await tr.json();

  let claims: Record<string, unknown>;
  try {
    claims = (await jwtVerify(tokens.id_token, JWKS, {
      issuer: ISSUER, audience: CLIENT_ID, algorithms: ["RS256"], maxTokenAge: "10m", clockTolerance: 60,
    })).payload;
  } catch {
    return deny("Could not verify the sign-in token.", 401);
  }
  const email = String(claims.preferred_username || claims.email || claims.upn || "").toLowerCase();
  if (!email.endsWith("@" + DOMAIN)) return deny(`Only @${DOMAIN} accounts can view this dashboard.`);
  if (GROUP_ID) {
    const groups = Array.isArray(claims.groups) ? (claims.groups as string[]) : [];
    if (!groups.includes(GROUP_ID)) return deny("Your account is not in the dashboard access group. Ask IT to add you.");
  }

  const now = Math.floor(Date.now() / 1000);
  const session = await mintSession({ email, name: String(claims.name || ""), jti: randomString(16), login: now }, url.origin);
  const target = safeReturnPath(flow.returnTo, url.origin);
  return redirect(target, [cookie(SESSION_COOKIE, session, IDLE_MINUTES * 60), cookie(FLOW_COOKIE, "", 0)]);
}

type Session = { email: string; name: string; jti: string; login: number };

/** Expiry = idle timeout from now, capped at the absolute lifetime measured from the original login. */
async function mintSession(sess: Session, origin: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.min(now + IDLE_MINUTES * 60, sess.login + SESSION_HOURS * 3600);
  return await new SignJWT({ email: sess.email, name: sess.name, login: sess.login })
    .setProtectedHeader({ alg: "HS256" }).setJti(sess.jti).setIssuer(origin).setAudience(SESSION_AUD)
    .setIssuedAt(now).setExpirationTime(exp).sign(secretKey());
}

async function isRevoked(jti: string): Promise<boolean> {
  try {
    return (await REVOKED().get(jti)) !== null;
  } catch (e) {
    console.error("revocation store unavailable:", e);
    return false;
  }
}

async function revoke(jti: string, login: number) {
  try {
    // keep the marker until the session could no longer be valid anyway
    await REVOKED().setJSON(jti, { revokedAt: Date.now(), expires: (login + SESSION_HOURS * 3600) * 1000 });
  } catch (e) {
    console.error("could not record logout:", e);
  }
}

/** A session is valid only if it was signed with our secret using HS256, is unexpired, was issued
 *  for this site, names an allowed account, is within the absolute lifetime, and has not been
 *  revoked by a logout. Anything else is treated as signed-out. */
async function validSession(token: string, origin: string): Promise<Session | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey(), {
      algorithms: ["HS256"], issuer: origin, audience: SESSION_AUD, maxTokenAge: `${IDLE_MINUTES}m`,
    });
    const email = typeof payload.email === "string" ? payload.email.toLowerCase() : "";
    const login = typeof payload.login === "number" ? payload.login : 0;
    const now = Math.floor(Date.now() / 1000);
    if (!email.endsWith("@" + DOMAIN) || !payload.jti || !login || now > login + SESSION_HOURS * 3600) return null;
    if (await isRevoked(payload.jti)) return null;
    return { email, name: String(payload.name || ""), jti: payload.jti, login };
  } catch {
    return null; // expired, tampered, wrong algorithm, or foreign token
  }
}

/** Cross-site request forgery guard for anything that is not a plain GET: the browser-supplied
 *  Origin (or Referer) must be this site. Combined with the SameSite=Lax session cookie. */
function sameOrigin(req: Request, origin: string): boolean {
  const o = req.headers.get("origin");
  if (o) return o === origin;
  const r = req.headers.get("referer");
  if (r) { try { return new URL(r).origin === origin; } catch { return false; } }
  return false;
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  if (!TENANT || !CLIENT_ID || !CLIENT_SECRET || SESSION_SECRET.length < 32) {
    return deny("Sign-in is not configured yet (missing ENTRA_* or SESSION_SECRET settings).", 503);
  }
  if (url.pathname === CALLBACK_PATH) return finishLogin(req, url);
  const cookieVal = readCookie(req, SESSION_COOKIE);
  const sess = cookieVal ? await validSession(cookieVal, url.origin) : null;

  if (url.pathname === LOGOUT_PATH) {
    if (sess) await revoke(sess.jti, sess.login);
    const back = encodeURIComponent(url.origin + "/");
    return redirect(`${LOGOUT}?post_logout_redirect_uri=${back}`, [cookie(SESSION_COOKIE, "", 0)]);
  }

  if (sess) {
    if (req.method !== "GET" && req.method !== "HEAD" && !sameOrigin(req, url.origin)) {
      return new Response("Cross-site request blocked", { status: 403 });
    }
    const res = await context.next();
    const out = new Response(res.body, res);
    out.headers.set("Cache-Control", "private, no-store");
    // sliding renewal: refresh the cookie once half the idle window has passed
    const now = Math.floor(Date.now() / 1000);
    const remaining = sess.login + SESSION_HOURS * 3600 - now;
    if (remaining > 0) {
      const iat = Number((await jwtVerify(cookieVal!, secretKey(), { algorithms: ["HS256"] })).payload.iat || now);
      if (now - iat > (IDLE_MINUTES * 60) / 2) {
        out.headers.append("Set-Cookie", cookie(SESSION_COOKIE, await mintSession(sess, url.origin), Math.min(IDLE_MINUTES * 60, remaining)));
      }
    }
    return out;
  }
  if (req.method !== "GET" && req.method !== "HEAD") return new Response("Sign in required", { status: 401 });
  return startLogin(url);
};

export const config: Config = { path: "/*" };
