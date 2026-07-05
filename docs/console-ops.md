# Console Ops — authenticated scan execution & user management

This document is the **spec** for the operational console: it was written
before the code, the code is required to match it, and the tests pin both.
It covers the threat model, the API surface, the authorization matrix, the
session/CSRF design, the bootstrap flow, and the deployment posture.

Scope shipped in this phase: login + sessions, three roles, registered-target
scan launching through a strictly serial job queue, user/target CRUD, and an
append-only audit log. The pipeline itself was extracted to
`internal/pipeline` so the CLI and the server run the *same* code path.

---

## 1. Posture summary (honest version)

- **Zero users on disk ⇒ the console is exactly what it was before this
  phase**: a read-only, loopback-bound viewer over `.appsec/runs`. No login
  page, no session checks on read routes; every operational endpoint answers
  `403` with a message naming the bootstrap command
  (`appsec user add --role admin`). Nothing to configure, nothing new to
  trust.
- **One or more users on disk ⇒ every `/api/*` route requires a session**,
  reads included. Mixed anonymous-read/authenticated-write is a footgun once
  the server can execute scanners, so the switch is all-or-nothing. The only
  exemptions are `POST /api/auth/login` (you cannot log in behind a login
  wall), `GET /api/auth/me` (the UI's "do I need to log in?" probe; returns
  auth state only), and `GET /api/health` (liveness: `{ok, time}`, nothing
  else). Static UI assets are served without a session — the login page is
  part of the SPA bundle.
- **The console still ships no TLS.** A login over plaintext HTTP is a
  credential disclosure to the network path. The supported way to leave
  loopback is a TLS-terminating reverse proxy in front (§8) — `appsec serve`
  itself refuses to pretend otherwise, and the non-loopback warning says so.
- **The browser can never supply a filesystem path or a scanner argument.**
  Scans launch against pre-registered target IDs with closed-enum options,
  validated server-side against the registry entry. Path validation happens
  once, at registration time, by an admin.

## 2. Threat model

Each row is an attack the new surface invites, and the design decision that
closes it. Tests referenced in §9 pin every row.

| # | Surface | Attack | Countermeasure |
|---|---------|--------|----------------|
| T1 | `POST /api/scans` | Free-text target path: scan `/etc`, another user's home, or a path crafted to hit adapter bugs | The scan API accepts an **opaque registry ID only**. The server never joins request input into a filesystem path. Unknown ID → 404. Registration (admin-only) validates: absolute, exists, is a directory, not `/`, no `..` after cleaning. |
| T2 | Scan options | Flag/argument smuggling into scanner binaries (`--config`, `-o`, shell metacharacters) | No CLI strings cross the API. Options are a **closed enum**: scanner subset (validated against the target's allowed list), profile (`fast\|standard\|max`), triage on/off. Adapters keep their fixed argv; nothing from the request reaches `exec.Command`. |
| T3 | Session cookies | CSRF on any mutating route | Every non-GET route requires `X-CSRF-Token` matching a per-session random token (constant-time compare). Cookie is `HttpOnly`, `SameSite=Strict`, `Secure` when the login arrived over TLS. Missing/wrong token → 403. |
| T4 | Login | Credential stuffing, username/timing oracles, plaintext at rest | Passwords stored as **argon2id** (m=64MiB, t=1, p=4, 16B salt, 32B key). Unknown usernames verify against a dummy hash so timing does not distinguish "no such user" from "wrong password", and both return the same 401 body. Login is rate-limited per-IP **and** per-username (5 failures/min, then locked for 5 min). |
| T5 | User CRUD | Privilege escalation, self-demotion lockout, IDOR | Role checks live in one server-side middleware table (§5); UI hiding is cosmetic. Deleting or demoting the **last admin is refused (409)**. User IDs are random; the list endpoint is admin-only anyway. |
| T6 | Password hashes | Hash disclosure via API/logs/audit | API responses use dedicated DTOs that have **no hash field** — the storage struct is never serialized outward (test asserts on raw JSON bytes). Hashes and session tokens never appear in logs or audit lines. |
| T7 | Concurrent scans | Overlapping Ollama triage calls (single serial queue), runstore write races, resource exhaustion | **One job executes at a time**, strictly serial worker. The pending queue is bounded (10); an 11th submission is rejected with 429, never buffered. Triage stays "enrichment, never a dependency". |
| T8 | Existing users | Breaking the local-first read-only workflow | Zero-config behavior byte-identical to the previous release (see §1). The pre-auth server tests still pass unmodified against the zero-users mode. |
| T9 | Session theft | Stolen/undying sessions | Opaque 256-bit random tokens (no JWT — revocable by deletion), server-side table, **idle expiry 2h, absolute expiry 24h**, session destroyed on logout, all sessions for a user destroyed on password change or delete. |
| T10 | Audit log | Log forging / secret leakage | Audit lines are structured JSONL written server-side only (append-only file, 0600). User-controlled strings appear only as JSON string values. No password material, no tokens, no finding content. |

Residual risk, stated plainly: no TLS in-process (§8); job/queue state is
in-memory (a restart forgets queue history — completed runs and the audit
file are the durable records); the users/targets/audit files are protected
by file permissions (0600), not encryption — an attacker with local file
access already owns the host.

## 3. On-disk layout

Everything lives under the served repo's `.appsec/` directory, which is
already `.gitignore`d wholesale (the existing rule that keeps `runs/` out of
version control covers these too):

| File | Contents | Mode |
|------|----------|------|
| `.appsec/users.json` | `{schema, users: [{id, username, hash, role, createdAt}]}` — argon2id encoded hashes | 0600 |
| `.appsec/targets.json` | `{schema, targets: [{id, name, path, scanners, profile, createdAt}]}` | 0600 |
| `.appsec/audit.jsonl` | append-only, one JSON object per line | 0600 |
| `.appsec/runs/*.json` | unchanged — frozen contract | 0644 |

Decision: the file is named `users.json` (not `console-users.json`) — it sits
inside an already-ignored directory and there is only one kind of user.

Decision: **run provenance lives in the audit log, not the run file.** The
runstore JSON shape is a frozen contract (it is `report.Document`, shared
with the `--format json` report); adding `launchedBy` would leak a console
concern into every CLI report. The `scan.launch`/`scan.finish` audit pair
carries who/target/options/runID and is the durable provenance record.

## 4. Roles

Three roles, strictly ordered: `viewer < operator < admin`.

| Role | May |
|------|-----|
| `viewer` | Read everything a logged-in user can see: summary, runs, findings, targets, job list/status |
| `operator` | Viewer + launch scans (`POST /api/scans`) |
| `admin` | Operator + user CRUD, target CRUD, read the audit log |

## 5. Authorization matrix

Authorization is **one table in one file** (`internal/server/authz.go`),
route pattern + method → minimum role, checked in middleware before any
handler runs. The UI hides what you cannot do; the server refuses it.

Legend for the zero-users column: `open` = behaves exactly as the pre-auth
console; `403+hint` = refused with a body naming `appsec user add`.

| Method | Route | Min role (users exist) | Zero users |
|--------|-------|------------------------|------------|
| GET | `/api/health` | none (exempt) | open |
| GET | `/api/auth/me` | none (exempt) | open |
| POST | `/api/auth/login` | none (exempt; rate-limited) | 403+hint |
| POST | `/api/auth/logout` | viewer | 403+hint |
| GET | `/api/summary` | viewer | open |
| GET | `/api/runs` | viewer | open |
| GET | `/api/runs/{id}` | viewer | open |
| GET | `/api/targets` | viewer | open |
| POST | `/api/targets` | admin | 403+hint |
| DELETE | `/api/targets/{id}` | admin | 403+hint |
| GET | `/api/scans` | viewer | open |
| GET | `/api/scans/{id}` | viewer | open |
| POST | `/api/scans` | operator | 403+hint |
| GET | `/api/users` | admin | 403+hint |
| POST | `/api/users` | admin | 403+hint |
| PATCH | `/api/users/{id}` | admin | 403+hint |
| DELETE | `/api/users/{id}` | admin | 403+hint |
| GET | `/api/audit` | admin | 403+hint |
| GET | `/` + static assets | none (SPA shell, includes login page) | open |

Notes:
- "Zero users / open" read routes exist so the local read-only workflow needs
  no setup. `GET /api/targets` and `GET /api/scans` return empty-but-valid
  payloads in that mode; they are listed `open` because they are reads with
  nothing sensitive in them, keeping the mode rule simple: *reads open,
  everything else 403+hint*.
- Unauthenticated request to a protected route → **401** (UI shows login).
  Authenticated but under-privileged → **403**. No-session on a mutating
  route fails authz (401) before CSRF is even considered.
- Status codes used by ops routes: `202` scan accepted, `429` queue full,
  `404` unknown target/job/user ID, `409` last-admin protection and duplicate
  username, `400` closed-enum violation.

## 6. Session & CSRF design

- **Login**: `POST /api/auth/login {username, password}`. On success the
  server issues an opaque token — 32 bytes from `crypto/rand`,
  base64url — stored server-side (keyed by SHA-256 of the token) with
  `{userID, role, csrfToken, createdAt, lastSeen}`. The response sets
  `appsec_session` (`HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` if the
  request arrived over TLS or `X-Forwarded-Proto: https`) and returns
  `{user: {username, role}, csrfToken}`.
- **CSRF**: the per-session CSRF token is returned by login and by
  `GET /api/auth/me`; the SPA sends it as `X-CSRF-Token` on every non-GET
  request. The middleware rejects any non-GET API request whose header does
  not match the session's token (constant-time compare) with 403.
  `SameSite=Strict` is the first layer; the token check is the second —
  both are enforced, and both are tested.
- **Expiry**: idle 2 hours (sliding on authenticated requests), absolute 24
  hours. Expired sessions are deleted on touch and swept opportunistically.
- **Revocation**: logout deletes the session; password change and user
  deletion delete all of that user's sessions. Opaque tokens make this exact
  (this is why there is no JWT).
- **Rate limiting** (login only): fixed 1-minute window, 5 failures per IP
  and 5 per username → that key is locked for 5 minutes; the limiter answers
  429 before credentials are checked. Success resets the counters.
- Passwords: argon2id via `golang.org/x/crypto/argon2`, parameters
  `m=65536 KiB, t=1, p=4`, 16-byte salt, 32-byte key, stored in the standard
  `$argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>` encoding (parameters are
  read back from the stored string, so they can be raised later without
  invalidating existing users). Minimum password length 8; no other
  composition rules.

## 7. Scan execution model

- **Registry**: targets are registered by an admin (CLI `appsec target
  add|list|remove` or the admin API) as
  `{id, name, path, scanners, profile}`. `id` is random hex, assigned by the
  server — the browser only ever echoes it back. Path validation at
  registration: absolute, `filepath.Clean`-stable, exists, is a directory,
  not `/`. Nothing else about the path is ever derived from request data.
- **Launch**: `POST /api/scans {targetId, options: {scanners?, profile?,
  triage?}}` (operator+). Options are validated against the registry entry:
  requested scanners must be a subset of the target's allowed scanners;
  profile must be one of the target's profile or `fast|standard|max`; triage
  is a boolean that flips `triage.enabled` — the provider, model, endpoint
  and every other triage setting come from the target repo's `appsec.yml`,
  never from the request. Accepted → `202 {job}`.
- **Queue**: strictly serial — one worker goroutine, one job running at any
  moment (this also protects the single-queue Ollama instance during
  triage). Pending queue is bounded at 10; beyond that submissions are
  rejected with 429 ("reject, don't buffer"). Job state
  (`queued|running|done|failed`, progress lines from the pipeline callback,
  run ID on success) is **in-memory**; `GET /api/scans` lists recent jobs,
  `GET /api/scans/{id}` is polled by the UI (no WebSockets by design).
- **Execution**: the worker calls `pipeline.Run` — the same function the CLI
  `scan` command now wraps — with the target repo's own `appsec.yml` as the
  config base. Findings are saved through the existing `runstore.Save` path
  **into the scanned target's own `.appsec/runs`**, exactly where
  `appsec scan --save` would put them. When the target is the served repo
  (the primary workflow: register the repo you're serving), the run appears
  in the console's runs list with no new read API. A target pointing at a
  different repo still scans and saves correctly, but its history lives with
  that repo — serve it to browse it. Mixing several repos' runs into one
  history would corrupt the delta/trend semantics, so we don't.
  Report writing to stdout/files is a CLI concern and does not happen for
  console-launched scans.
- **Audit**: `scan.launch` (actor, target ID, options) on acceptance,
  `scan.finish` (job ID, run ID or error class) on completion.

### `internal/pipeline` extraction

`pipeline.Run(ctx, Options{Target, Config}, progress)` owns: adapter
selection, parallel scanner execution with per-adapter timeouts, normalize →
ignore-filter → correlate → triage (enrichment-only) → risk → compliance →
optional false-positive exclusion. `progress` receives the exact
pre-formatted lines the CLI used to print — the CLI writes them verbatim to
stderr (byte-identical output, verified against a golden capture), the
server appends them to job progress. Report writing, run saving, the summary
line and the severity gate stay with the caller: the CLI must write the
report *before* saving (a failed report write must not leave a saved run),
and the server saves but never writes reports.

## 8. Deployment: leaving loopback

`appsec serve` binds `127.0.0.1:8080` and terminates no TLS. That is a
feature: TLS config is deployment-specific and doing it badly is worse than
not doing it. **The supported way to expose the console is a
TLS-terminating reverse proxy** (Caddy, nginx, Traefik) on the same host:

```
caddy reverse-proxy --from console.example.internal --to 127.0.0.1:8080
```

The proxy must pass `X-Forwarded-Proto: https` so the session cookie is
marked `Secure`. Widening `--addr` directly still prints a warning: with
zero users it is the old NO-AUTH warning; with users it warns that
credentials will cross the network in cleartext without a TLS proxy.

## 9. Test map (security first)

| Pin | Test |
|-----|------|
| Authz matrix (§5) | table-driven: every route × {no session, viewer, operator, admin} × {zero-users, users-exist} → expected status |
| CSRF | non-GET with missing/wrong token → 403; correct token → 2xx |
| Login rate limit | 6th failure in window → 429; correct password while locked → 429 |
| Timing/oracle | unknown user and wrong password return identical status+body |
| Last admin | delete/demote sole admin → 409; works once a second admin exists |
| Hash leakage | raw JSON of every user-bearing response asserted to contain no `$argon2` / `hash` material |
| Target registry | unknown target ID → 404; `target add` with relative / `..` / file / `/` → rejected |
| Serial queue | two POSTed scans: second stays `queued` until first finishes; 11th pending → 429 |
| Zero-users mode | pre-existing server tests unchanged; ops routes → 403 naming the bootstrap command |
| Pipeline | golden capture: `appsec scan` stdout/stderr/exit codes byte-identical pre/post extraction |

## 10. Bootstrap walkthrough

```bash
# 1. Create the first admin (CLI only — there is no open registration API).
cd /path/to/repo
appsec user add alice --role admin            # prompts for password (no echo)
# or, for scripting:
echo -n 's3cret-passphrase' | appsec user add alice --role admin --password-stdin

# 2. Register what may be scanned (admin).
appsec target add /abs/path/to/repo --name "payments-api" --scanners semgrep,gitleaks

# 3. Serve and log in.
appsec serve            # http://127.0.0.1:8080 now shows a login page

# 4. Onboard teammates from the console (admin → Users) or the CLI:
appsec user add bob --role viewer
appsec user add carol --role operator

# 5. Operate: pick a target, choose scanners/profile/triage, Launch.
#    Watch the job progress; the finished run lands in Runs as usual.
#    Admins can review every action under Audit.
```

`appsec user list|passwd|remove` and `appsec target list|remove` complete
the lifecycle. All user/target commands take `--dir` like `serve` does.

## 11. Explicit non-goals (this phase)

No OIDC/SSO/LDAP/passkeys (the session layer is deliberately swappable), no
in-process TLS, no scheduling, no multi-tenancy, no per-target permissions,
no scanner-arg or config upload from the UI, no finding suppression from the
console, no WebSockets.
