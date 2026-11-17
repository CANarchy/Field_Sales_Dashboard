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
//   SESSION_HOURS        optional: session length in hours (default 8)

import type { Config, Context } from "https://edge.netlify.com/v1/index.ts";
import { createRemoteJWKSet, jwtVerify, SignJWT } from "npm:jose@5.9.6";

const env = (k: string, d = "") => Netlify.env.get(k) ?? d;
const TENANT = env("ENTRA_TENANT_ID");
const CLIENT_ID = env("ENTRA_CLIENT_ID");
const CLIENT_SECRET = env("ENTRA_CLIENT_SECRET");
const SESSION_SECRET = env("SESSION_SECRET");
const GROUP_ID = env("ENTRA_GROUP_ID");
const DOMAIN = env("ALLOWED_DOMAIN", "monsterbrewing.com").toLowerCase();
const SESSION_HOURS = Number(env("SESSION_HOURS", "8")) || 8;

const ISSUER = `https://login.microsoftonline.com/${TENANT}/v2.0`;
const AUTHZ = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`;
const TOKEN = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`;
const LOGOUT = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/logout`;
const JWKS = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`));

const SESSION_COOKIE = "fsd_session";
const SESSION_AUD = "field-survey-dashboard";
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

  const session = await new SignJWT({ email, name: claims.name || "" })
    .setProtectedHeader({ alg: "HS256" }).setIssuer(url.origin).setAudience(SESSION_AUD)
    .setIssuedAt().setExpirationTime(`${SESSION_HOURS}h`).sign(secretKey());
  const target = safeReturnPath(flow.returnTo, url.origin);
  return redirect(target, [cookie(SESSION_COOKIE, session, SESSION_HOURS * 3600), cookie(FLOW_COOKIE, "", 0)]);
}

/** A session is valid only if it was signed with our secret using HS256, is unexpired, was issued
 *  for this site, and still names an allowed account. Anything else is treated as signed-out. */
async function validSession(token: string, origin: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, secretKey(), {
      algorithms: ["HS256"], issuer: origin, audience: SESSION_AUD, maxTokenAge: `${SESSION_HOURS}h`,
    });
    const email = typeof payload.email === "string" ? payload.email.toLowerCase() : "";
    return email.endsWith("@" + DOMAIN);
  } catch {
    return false; // expired, tampered, wrong algorithm, or foreign token
  }
}

export default async (req: Request, context: Context) => {
  const url = new URL(req.url);
  if (!TENANT || !CLIENT_ID || !CLIENT_SECRET || SESSION_SECRET.length < 32) {
    return deny("Sign-in is not configured yet (missing ENTRA_* or SESSION_SECRET settings).", 503);
  }
  if (url.pathname === CALLBACK_PATH) return finishLogin(req, url);
  if (url.pathname === LOGOUT_PATH) {
    const back = encodeURIComponent(url.origin + "/");
    return redirect(`${LOGOUT}?post_logout_redirect_uri=${back}`, [cookie(SESSION_COOKIE, "", 0)]);
  }

  const session = readCookie(req, SESSION_COOKIE);
  if (session && (await validSession(session, url.origin))) {
    {
      const res = await context.next();
      const out = new Response(res.body, res);
      out.headers.set("Cache-Control", "private, no-store");
      return out;
    }
  }
  if (req.method !== "GET") return new Response("Sign in required", { status: 401 });
  return startLogin(url);
};

export const config: Config = { path: "/*" };
