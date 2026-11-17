# Monster Brewing Field Survey Dashboard — automated build

Rebuilds https://mbrewfielddashboard.netlify.app/ every Monday morning straight from Power BI
and deploys it to Netlify. No exports, no uploads. The site URL never changes.

```
Power BI (KARMA model) ──┐
                         ├─► build_from_powerbi.py ─► dist/index.html ─► Netlify CLI ─► live site
Power BI (Depletions) ───┘
```

## What's in this repo

| File | Purpose |
|---|---|
| `build_from_powerbi.py` | Pulls surveys + buyer commitments (KARMA model) and distributors, chain flags, case equivalents (Depletions model); renders the page |
| `template/dashboard.html` | The dashboard itself (HTML/CSS/JS, logos, map) with `__ROWS__`, `__BUY__`, `__EMPMAP__` placeholders |
| `netlify/edge-functions/auth.ts` | Company SSO: every request is checked at Netlify's edge against Microsoft Entra ID before the page is served |
| `netlify.toml` | Publish directory and security headers (the edge function declares its own `/*` route) |
| `build_from_exports.py` | Fallback when Power BI isn't reachable: `python3 build_from_exports.py <ResultsByForm.xlsx> <BuyerCommitments.xlsx> --out dist` renders the same page from KARMA grid exports |
| `empmap.json` | Employee → `[title, manager]`. **Edit this when reps join or move.** Manager drives the Manager filter |
| `dist_codes.json` | Distributor code → name fallback for codes not in the Depletions Bottler table |
| `.github/workflows/build.yml` | Monday 06:00 ET schedule + manual "Run workflow" button |
| `tests/fixture.json` | Small sample for a local dry run: `python3 build_from_powerbi.py --fixture tests/fixture.json` |

## One-time setup

### 1. IT: Power BI service principal (the only blocker)
Ask IT for a Microsoft Entra ID **app registration** and give you:
- Tenant ID (`f01d65ba-e57e-4f8f-8143-a43ed634f3c2`), Application (client) ID, and a client secret
- In the Power BI admin portal → Tenant settings → **Developer settings** → *Allow service principals to use Power BI APIs* enabled for a security group containing the app
- The app added as **Member** (or Contributor) of the **Monster Brewing** workspace, so it can run queries against
  `MBrew KARMA Preview` (07f05c80-…) and `Monster Brewing Depletions Dashboard` (53e6e702-…)

No API permissions need to be granted on the app registration itself — workspace membership is what authorizes `executeQueries`.

### 2. IT: Entra ID app registration for the sign-in (company SSO)
The dashboard is protected by Microsoft Entra ID. Visitors are sent to the normal Microsoft sign-in page and only
`@monsterbrewing.com` accounts (optionally only members of one security group) get through. The check runs on Netlify's
edge, so an unsigned-in visitor never receives the page or its data. Ask IT to create a second app registration
(the Power BI one from step 1 can be reused if IT prefers, but a separate one keeps the permissions apart):

- **Supported account types**: *Accounts in this organizational directory only (single tenant)*
- **Redirect URI** (platform *Web*): `https://mbrewfielddashboard.netlify.app/.auth/callback`
  (add the same path on any custom domain you later attach)
- **Authentication → ID tokens**: leave the implicit grant boxes *unchecked* (the site uses the authorization-code flow with PKCE)
- **Certificates & secrets**: create a client secret; note the *value* and its expiry (set a calendar reminder to rotate it)
- **API permissions**: the default `User.Read` / `openid` / `profile` / `email` delegated permissions are enough; grant admin consent
- Optional, to limit access to a specific group: **Token configuration → Add groups claim → Security groups**, and in
  *Enterprise applications → the app → Properties* set **Assignment required = Yes** and assign that group

IT gives you: Tenant ID, Application (client) ID, client secret value, and (optional) the group's Object ID.

### 3. Netlify
- Site settings → General → **Site ID** (copy it)
- User settings → Applications → **Personal access tokens** → New access token (copy it)
- Site configuration → **Environment variables** → add (scope: all, or Production only):

| Variable | Value |
|---|---|
| `ENTRA_TENANT_ID` | from IT (`f01d65ba-e57e-4f8f-8143-a43ed634f3c2`) |
| `ENTRA_CLIENT_ID` | from IT |
| `ENTRA_CLIENT_SECRET` | from IT (the secret *value*) |
| `SESSION_SECRET` | any random string of 32+ characters, e.g. the output of `openssl rand -base64 48` |
| `SITE_URL` | `https://mbrewfielddashboard.netlify.app` (the one address the site answers on; all sign-in redirects are built from it) |
| `ENTRA_GROUP_ID` | optional but recommended: Object ID of the access group; needs the *groups claim* from step 2 |
| `ALLOWED_DOMAIN` | optional: defaults to `monsterbrewing.com` |
| `SESSION_HOURS` | optional: hard lifetime of a sign-in, 1–12, default 8 |
| `IDLE_MINUTES` | optional: sign in again after this long with no activity, 5–120, default 60 |

How access is decided: the ID token from Microsoft is verified (signature, issuer, audience, nonce), then the user
is authorized by **tenant ID + object ID** from that token; the sign-in name must also be on `ALLOWED_DOMAIN`, and
if `ENTRA_GROUP_ID` is set the token must list that group (a missing groups claim is a refusal, not a pass).

Sessions are a signed, HttpOnly `__Host-` cookie that renews while the user is active and expires after
`IDLE_MINUTES` of inactivity or `SESSION_HOURS` after login, whichever is first; nobody's password is ever stored or
seen by the site. The **Sign out** link in the toolbar opens `/.auth/logout`, which asks for confirmation; the
sign-out itself is a same-site POST with a CSRF token that revokes the session server-side (its id is written to a
Netlify Blobs store named `revoked-sessions`, checked on every request) and then ends the Microsoft session, so a
copied cookie stops working at logout. Netlify Blobs is on by default. If that store cannot be reached, or the
function hits any other error, the site returns a 503 page instead of serving the dashboard (fails closed).
Requests on any address other than `SITE_URL` (deploy previews included) are redirected to it.

### 4. GitHub
Create a private repo, push these files, then **Settings → Secrets and variables → Actions → New repository secret** for each:

| Secret | Value |
|---|---|
| `PBI_TENANT_ID` | from IT |
| `PBI_CLIENT_ID` | from IT |
| `PBI_CLIENT_SECRET` | from IT |
| `NETLIFY_AUTH_TOKEN` | Netlify personal access token |
| `NETLIFY_SITE_ID` | Netlify site ID |

Then **Actions → Build dashboard from Power BI → Run workflow** to test. The Netlify CLI deploy bundles the
edge function from `netlify/edge-functions/` along with `dist/`. The run log shows survey and
commitment counts, and the finished `index.html` is attached to the run as an artifact if you want to inspect it.

## Weekly operation
Nothing. The workflow runs Monday 06:00 ET. To refresh mid-week, press *Run workflow*.
If the log shows a `NEW EMPLOYEES` warning, add them to `empmap.json` with their title and manager and commit —
the next run picks it up.

## How the data is shaped
- **Surveys**: forms `MBREW B.T.B. 2026` and `MBREW B.T.B. 2026 - NY`, from `SURVEY_START` (2026-07-01).
  One dashboard row per (outlet, rep, timestamp). Account = store name + store number; chain = store name when
  VIP flags the outlet as *Chain*, otherwise *Independents*; distributor = the outlet's VIP distributor, named via the
  Depletions Bottler table; soft-drink bottlers are dropped.
- **Commitments**: forms `Buyer Commitments` and `Buyer Commitments - UT`. One block per (outlet, distributor, rep);
  commitments accumulate across visits; survey dates are the real KARMA submission dates.
- **Status**: `FULFILLED` when the outlet has case-equivalent depletions from that distributor in the trailing
  3-month window (first of the month two months before the latest invoice, through the latest invoice); otherwise `OPEN`.
- **Data lag**: the KARMA model usually trails KARMA by a few days and Depletions by about a week; the run log prints both dates.

## Changing the dashboard
Edit `template/dashboard.html` (the UI) — never the generated `dist/index.html`. The three placeholders must stay.
Run the fixture build locally to check it still renders, then commit.

## Security notes (code-scanning findings, Nov 2026)
- Survey text, photo labels and photo URLs come from KARMA and are treated as untrusted: they are HTML-escaped,
  URLs are only used if they are `https://` on the KARMA/VIP media hosts (`karma.vtinfo.com`, `api.vtinfo.com`), and thumbnails use data attributes + delegated handlers (no inline
  `onclick`/`onerror` built from data). The build escapes `</` inside the embedded JSON so a note can never close the
  `<script>` block.
- After sign-in the user always lands on `SITE_URL/`; redirect targets come from configuration, never from the request.
- No page content is built by inserting data into HTML strings unescaped; the header subtitle and map tooltips use text nodes.
- Requests other than GET (the feedback form, sign-out) must carry a same-site `Origin`/`Referer` header in addition to the
  `SameSite=Lax` session cookie, which blocks cross-site request forgery.
- The Excel export library is loaded from cdnjs with a Subresource Integrity hash pinned to SheetJS 0.18.5, so a
  tampered copy will not run (the export then falls back to CSV).
- CSV exports prefix any cell starting with `=`, `+`, `-`, `@`, tab or CR so spreadsheets don't execute it as a formula.
- The former client-side login (`wrapper.html`, embedded decryption key, "remember me" password storage) is gone;
  access control is the Entra ID edge function above.
