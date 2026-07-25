# laravel-otp — Design Specification

**Date:** 2026-07-25
**Package:** `thecyrilcril/laravel-otp`
**Status:** Approved (brainstormed and reviewed section-by-section with the owner)

## Purpose

A purpose-scoped, hashed, rate-limited one-time-password package for Laravel, extracted from
the hand-rolled implementations in `~/Code/binitng` (`app/Concerns/HasOtp.php`) and
`~/Code/dexlink` (`app/Traits/HasEmailVerificationOtp.php`), hardened with the controls both
lack. Consolidates three prospective consumers (binitng, dexlink, kitwire) onto one tested
implementation.

Package research (July 2026, recorded in kitwire's
`docs/plans/2026-07-25-001-refactor-owned-email-verification-plan.md` appendix) found no
existing package offering all three required properties — purpose scoping, hashed-at-rest
storage, and rate limiting. Spatie's stores plaintext with no purpose scoping; otpz has no
purposes; otpify has no rate limiting; ichtrojan is actively unsafe.

## Scope

**In:** the package itself — repo, source, config, migration, tests, CI, Packagist publish.

**Out (deliberate):** migrating binitng, dexlink, or kitwire onto it. Each migration is
separate follow-up work per project. The README includes a migration guide sketch only.

## Decisions (with rationale)

| # | Decision | Rationale |
|---|---|---|
| D1 | Package only this pass | Focused deliverable; API validated by its own suite before consumers freeze it |
| D2 | Polymorphic `otpable` morphs, not a user FK | binitng keys users by uuid, dexlink by bigint; morphs serve both with zero config. Cost: no DB-level FK — accepted because rows live minutes and `MassPrunable` cleans up |
| D3 | Consumer owns delivery; `issueOtp()` returns plaintext once | Both consumers already own notification classes; package stays free of mail/SMS/queue/i18n opinions |
| D4 | Trait + focused internal services (Approach A) | Migrates mechanically from binitng's trait; matches `laravel-impersonate` idiom; each security control gets an isolated, testable home |
| D5 | Optional `context` target binding | Restores the defense Laravel's own link flow has (the `sha256(email)` URL hash) that code-based flows silently lost. Binds a code to the address it was sent to |
| D6 | bcrypt via the `hashed` cast | Framework-native, same primitive as `DatabaseTokenRepository`; nothing reversible at rest (both origin implementations use the reversible `encrypted` cast) |
| D7 | Support matrix: PHP `^8.4`, `illuminate/*` `^12\|\|^13` | Matches `thecyrilcril/laravel-impersonate` |

## Repository layout

Tooling mirrors `~/Code/laravel-impersonate`: Pest + orchestra/testbench, Pint, PHPStan,
same CI workflow shape, MIT, auto-discovered provider.

```
thecyrilcril/laravel-otp
├── composer.json                  php ^8.4, illuminate ^12|^13
├── config/otp.php
├── database/migrations/create_otps_table.php
├── src/
│   ├── OtpServiceProvider.php
│   ├── Concerns/HasOtps.php               ← the one consumer-facing trait
│   ├── Contracts/OtpPurpose.php           ← interface consumer enums implement
│   ├── Models/Otp.php
│   ├── Support/CodeGenerator.php          ← random_int, zero-padded
│   ├── Support/OtpLimiter.php             ← wraps Illuminate RateLimiter
│   ├── IssuedOtp.php                      ← readonly result object
│   ├── Events/OtpIssued.php
│   ├── Events/OtpVerified.php
│   ├── Events/OtpVerificationFailed.php
│   └── Exceptions/OtpThrottledException.php
└── tests/
```

## Public API

One trait, one contract, one result object.

```php
// Concerns/HasOtps.php — on any Eloquent model
issueOtp(OtpPurpose $purpose, ?string $context = null): IssuedOtp
verifyOtp(OtpPurpose $purpose, string $code, ?string $context = null): bool   // checks; never invalidates on success
consumeOtp(OtpPurpose $purpose, string $code, ?string $context = null): bool  // check + delete, atomic

// Both count failed checks against the limiter and the per-row attempts counter —
// verifyOtp is "non-destructive on success", not side-effect-free, or it would be
// a counter-free brute-force channel.

// Contracts/OtpPurpose.php
value(): string    // trivially satisfied by any backed string enum
                   // (binitng's OtpPurpose and dexlink's OtpType plug in without renaming cases)

// IssuedOtp — readonly
$issued->code       // plaintext, one-time exposure, for the consumer's notification
$issued->expiresAt  // CarbonImmutable
```

`issueOtp` deletes any existing row for that purpose first (one active code per
model+purpose), checks the issue limiter, generates, stores hashed, fires `OtpIssued`,
returns the plaintext exactly once. The package's involvement ends at the return — the
consumer feeds `$issued->code` into its own notification (mail, SMS, any channel).

### Context binding (D5)

`context` is "the target this code was sent to" — an E164 phone, an email address, any
string. When issued with a context, verification fails unless the same context is presented
at verify/consume time; when issued without, no context check occurs.

Closes the change-target hole: user requests a code for phone A, edits the pending field to
phone B, submits the code received on A — without binding, B gets verified having never
received anything. Laravel's link-based email verification prevents exactly this via the
`hash` URL parameter; codes have no URL to carry it, so the package carries it in the row.

```php
$user->issueOtp(Purpose::PhoneVerification, context: '+2348012345678');
$user->consumeOtp(Purpose::PhoneVerification, $code, context: $submittedPhone);

$user->issueOtp(Purpose::EmailVerification, context: 'new@example.com');

$user->issueOtp(Purpose::TwoFactorLogin);   // no target to bind — omit
```

## Schema

`otps` table (name configurable):

| Column | Type | Notes |
|---|---|---|
| `id` | bigint auto | package-internal key |
| `otpable_type` / `otpable_id` | morphs (string id) | works with uuid and bigint parents |
| `purpose` | string, part of composite index | from the consumer's enum `value()` |
| `code` | string | `hashed` cast — bcrypt at rest |
| `context` | string nullable | plaintext (an address, not a secret); compared with `hash_equals` |
| `attempts` | unsigned small int, default 0 | per-row failed-attempt counter |
| `expires_at` | timestamp | default now + 10 min (config) |
| `created_at` / `updated_at` | timestamps | |

Composite index `(otpable_type, otpable_id, purpose)` — every lookup is a single-row seek.
`MassPrunable` deletes expired rows on the consumer's `model:prune` schedule.

## Security controls

Mapped from the twelve-point failure-mode checklist in the kitwire plan appendix; each has a
specific home and an attack-shaped test.

1. **Generation** — `CodeGenerator`: `random_int(0, 10^N − 1)`, zero-padded. Length from
   config, default 6, **floor of 6 enforced** — configuring 4 throws.
2. **Storage** — `hashed` cast (bcrypt). A leaked database yields no live codes.
3. **Verification order** — rate limit → row lookup → expiry → `Hash::check` → context
   `hash_equals`. Limiter first: a brute-forcer cannot even cause bcrypt work.
4. **Enumeration resistance** — every failure path returns the same `false`; events carry
   the precise reason internally, the caller gets one bit.
5. **Verify rate limiting** — `OtpLimiter` (wraps Illuminate `RateLimiter`): default
   5 attempts/min per model+purpose, **plus** the per-row `attempts` counter — 5 failed
   checks kill that OTP outright even if the limiter window rolled over (otpz's defense
   against slow-drip brute force).
6. **Issue rate limiting** — default 3 sends per 10 min per model+purpose. Stops mail/SMS
   bombing and stops an attacker DoS-ing a victim by endlessly regenerating their code.
   Throttled calls throw `OtpThrottledException` carrying retry-after seconds.
7. **Single-use, race-safe** — `consumeOtp` runs check-and-delete in `DB::transaction`
   with `lockForUpdate`; two simultaneous submissions cannot both succeed.
8. **Expiry** — `expires_at`, default 10 minutes, config-tunable.
9. **Cleanup** — `MassPrunable`.
10. **Purpose scoping** — every query filters by purpose; an email-verification code can
    never satisfy a password-reset check.
11. **Target binding** — the `context` mechanism (D5).
12. **Secrets hygiene** — `#[SensitiveParameter]` on all code parameters; `IssuedOtp`
    masks the code in `__debugInfo`.

## Configuration (`config/otp.php`)

The whole surface — no model swapping, no action overriding:

```php
'length'        => 6,                       // minimum 6 enforced at runtime
'expires_after' => 10,                      // minutes
'verify_limit'  => ['attempts' => 5, 'decay' => 60],    // per model+purpose
'issue_limit'   => ['attempts' => 3, 'decay' => 600],   // per model+purpose
'max_attempts'  => 5,                       // per-row counter
'table'         => 'otps',
```

## Events

All carry the model and purpose — never the plaintext code.

| Event | When | Notes |
|---|---|---|
| `OtpIssued` | after row creation | audit-log hook (e.g. binitng's activity timeline) |
| `OtpVerified` | after successful consume | |
| `OtpVerificationFailed` | any failed verify/consume | carries reason enum: `NotFound`, `Expired`, `CodeMismatch`, `ContextMismatch`, `Throttled` — precise logging/alerting while the UI shows one generic message |

## Data flow (phone verification example)

1. Consumer: `$user->issueOtp($purpose, context: $phone)` → old row deleted → issue limiter
   → generate → store hashed → `OtpIssued` → returns `IssuedOtp` with plaintext.
2. Consumer feeds `$issued->code` into its own SMS notification. Package involvement ends.
3. User submits code → `$user->consumeOtp($purpose, $code, context: $phone)` → limiter →
   lock → expiry → `Hash::check` → context `hash_equals` → delete → `OtpVerified` — or
   `false` plus a failure event.

## Testing

Pest on orchestra/testbench, mirroring impersonate's setup. The security checklist doubles
as the test plan, proven **by attack**, not just happy path:

- brute-force past the limiter → assert throttle + `OtpThrottledException` retry-after
- replay a consumed code → fails
- submit at expiry + 1s → fails
- issue for phone A, consume with phone B → fails with `ContextMismatch`
- two parallel consumes of one code → exactly one wins
- config `length: 4` → throws
- stored value ≠ plaintext; is a bcrypt hash
- exception messages and event payloads never contain the plaintext code
- per-row counter kills a code after 5 failures even across limiter windows

Mechanical coverage: the contract works with both consumers' real enum shapes; morphs work
with uuid and bigint parents; prunable deletes only expired rows; issue replaces any prior
code for the same purpose; codes for different purposes coexist independently.

## CI and release

Same `ci.yml` shape as impersonate: Pint check, PHPStan, Pest across the support matrix.
Tag `v0.1.0` when green; publish to Packagist as `thecyrilcril/laravel-otp`. README covers
the API, the security model, and a migration guide sketch for binitng/dexlink.

## Alternatives considered and rejected

- **Broker style (`Otp::broker('email-verification')->issue($user)`)** — stringly-typed
  names, more config surface, and neither consumer's code maps onto it; rewrites instead of
  migrations.
- **Direct port of binitng's `HasOtp`, minimally generalized** — fastest, but inherits the
  exact gaps the extraction exists to fix (encrypted-not-hashed, no rate limiting) and would
  publish them with a wider blast radius.
- **Adopting `spatie/laravel-one-time-passwords`** — rejected earlier in the research phase:
  plaintext storage and no purpose scoping mean overriding its model, consume action, and
  schema — forking a package while inheriting its upgrade risk.
