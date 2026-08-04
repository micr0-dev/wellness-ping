# v2.0 Security Fixes - task list

Status key: `[x]` done · `[ ]` pending

## Critical - silent disarm of the switch

- [x] **C1** Inbound email `From` trusted with no authentication → verify DKIM/SPF via
  Postmark `Authentication-Results`, require domain alignment, and require a
  per-cycle reply code in the body instead of the static word "PONG".
- [x] **C2** `strings.Contains(body,"pong")` matches quoted text and autoresponders →
  strip quoted sections and reply separators, reject `Auto-Submitted` /
  `Precedence: bulk|auto_reply` / null-return-path messages.
- [x] **C3** HTML injection in `sendReplyEmail` (unescaped inbound body reflected into
  outbound HTML mail) → route through the escaping `plainToHTML`.
- [x] **C4** `GET /pong?token=` completes a check-in → mail link scanners disarm the
  switch. Require an explicit POST confirmation.

## High

- [x] **H5** No rate limiting or attempt caps anywhere → add limiter for `/send-code`,
  `/verify-code`, PIN and TOTP steps, and `/pong`; GC `PendingVerifications`.
- [x] **H6** PINs hashed with one round of SHA-256 → argon2id, constant-time compare,
  transparent upgrade of legacy sha256/plaintext values on next success.
- [x] **H7** Session cookies missing `Secure`; no security headers; no server timeouts.
- [x] **H8** `data/users.json` written `0644` → `0600`, dir `0700`, atomic replace.
- [x] **H9** Duress PIN detectable by response latency and by continued reminder mail →
  dispatch alerts asynchronously and make the outward state match a real check-in.

## Medium

- [x] **M10** WebAuthn dev origins (`localhost:8080/8087`) hardcoded into production config.
- [x] **M11** `checkInFlows` entries never expire (`StartedAt` written, never read).
- [x] **M12** `updateHandler` regenerates `user.Token`, invalidating in-flight check-in links.
- [x] **M13** Data races: scheduler and handlers touch `*User` fields without the lock;
  `updateHandler` swaps the pointer out from under the scheduler.
- [x] **M14** Scheduler blocks on `signal-cli` (up to ~17 min for 10 contacts), stalling
  every other user's pings and alerts.
- [x] **M15** `classifyContact` accepts garbage as a phone number; delivery failures are
  logged and never surfaced to the user.
- [x] **M16** `verifyTurnstile` fails open when the secret is unset.
- [x] **M17** No notification when contacts, modules, pause or service state change.
- [x] **M18** Unescaped `Fprintf` of `user.Email` into HTML responses.

## Additional items found while fixing

- [x] **A19** CSRF tokens on state-changing POSTs (SameSite=Strict alone is not enough).
- [x] **A20** Verification codes and check-in links written to logs when
  `POSTMARK_TOKEN` is unset.
- [x] **A21** Check-in token leaks via `Referer` (token is in the URL) → `Referrer-Policy`.
- [x] **A22** Inline `<script>` blocks prevent a strict CSP → move to `/static/*.js`.
- [x] **A23** No PIN quality floor; duress PIN may equal the real PIN.

---

## Verification

All of the above build clean and pass `go vet`, `gofmt` and `go test -race -count=3`.

`main_test.go` is new and locks in the behaviour that matters, so these cannot
regress silently:

| Test | Guards against |
| --- | --- |
| `TestInboundRejectsSpoofedSender` | C1 - spoofed `From` disarming the switch |
| `TestVerifyInboundAuthRequiresAlignedPass` | C1 - unaligned DKIM accepted |
| `TestNewContentStripsQuotedText`, `TestIsAutomatedRejectsAutoresponders` | C2 - autoresponders checking a user in |
| `TestPlainToHTMLEscapesInjectedMarkup`, `TestReplyAcknowledgementDoesNotLinkifyQuotedText` | C3 - HTML injection into outbound mail |
| `TestGetPongDoesNotCheckIn` | C4 - link scanners disarming the switch |
| `TestPINStepCannotBeSkipped`, `TestPINAttemptsAreLimited` | module bypass and PIN brute force |
| `TestDuressLooksExactlyLikeSuccess` | duress being observable |
| `TestVerifySecretUpgradesLegacyFormats` | H6 - hashing and legacy migration |
| `TestClassifyContactRejectsGarbage` | M15 - undeliverable emergency contacts |
| `TestUpdateRequiresCSRFToken` | A19 - CSRF |
| `TestExpiredFlowDoesNotRetainCompletedSteps` | M11 - stale satisfied steps |
| `TestRedactForLog` | A20 - secrets in logs |

Manually exercised against a running instance: security headers, GET-vs-POST
check-in, all four inbound rejection paths plus the accepted one, unauthenticated
`/settings` and `/update`, static-path traversal, fail-closed startup, and the
reply-code backfill.

## Two findings from re-reviewing my own changes

1. **The duress path was distinguishable.** Making the check-in require an
   explicit POST (C4) accidentally gave duress a *shorter* journey: the correct
   PIN redirected to a confirm page, while the duress PIN rendered "Confirmed"
   immediately. Anyone watching over the user's shoulder would see the missing
   step. The duress PIN now marks the flow and follows byte-for-byte the same
   sequence of pages and redirects; the alert fires at the final confirmation.
   `TestDuressLooksExactlyLikeSuccess` compares both response bodies.

2. **The duress path did a synchronous disk write** that the normal path did
   not, which is a timing signal. Persistence and alerting are now both
   dispatched off the request path.

## New environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `APP_ENV` | no | `development` relaxes Turnstile, HSTS and inbound auth. Never set in production. |
| `BASE_URL` | **yes** | Public origin for check-in links. |
| `WEBAUTHN_RPID` / `WEBAUTHN_ORIGIN` | **yes** | Dev origins are no longer compiled in. |
| `WEBAUTHN_DEV_ORIGINS` | no | Only honoured when `APP_ENV=development`. |
| `TRUST_PROXY` | no | Set only behind a proxy that overwrites `X-Forwarded-For`. |
| `INSECURE_COOKIES` | no | Local HTTP development only. |
| `POSTMARK_FROM` | no | Defaults to `ping@wellness-p.ing`. |
| `DEFAULT_COUNTRY_CODE` | no | Defaults to `1`. |
| `INBOUND_ALLOW_UNAUTHENTICATED` | no | Development only, and ignored unless `APP_ENV=development`. |

Startup now **fails closed**: missing `POSTMARK_TOKEN`, `INBOUND_SECRET`,
`TURNSTILE_SECRET_KEY`, `BASE_URL` or `WEBAUTHN_RPID` is fatal in production.

## Deployment notes

- **Reply-PONG needs a reply code.** Existing users are backfilled on first
  load, but the code only reaches them in their next check-in message. Between
  deploy and that message, replying will not check them in. The link always
  works.
- **The check-in link now needs one click.** Worth mentioning in release notes.
- **Verify Turnstile against the new CSP in staging.** The policy allows
  `challenges.cloudflare.com` only when `TURNSTILE_SITE_KEY` is set.
- **Argon2id uses 32 MiB per verification.** Fine at this scale given the
  attempt limits, but size the host accordingly.
- `data/users.json` is re-chmodded to `0600` on load.

## Not addressed

- Store-wide encryption at rest. TOTP secrets remain plaintext in the data
  file; as the original commit notes, full-disk encryption plus a key on the
  same host adds little. Worth revisiting only with a real KMS or operator
  passphrase.
- Sessions and pending codes are still persisted in the same JSON file.
- Single-process, in-memory rate limiting: a restart clears the budgets. This
  errs towards letting a real user check in, which is the right side to fail on.
