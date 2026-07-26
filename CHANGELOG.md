# Changelog

## v0.1.2 — 2026-07-26

Concurrency and serialization hardening, from an adversarial security audit.
No public API signature changes; two behavioral changes are noted below.

**Fixed**

- **Verification no longer holds a row lock across bcrypt.** The check ran
  inside a transaction holding `lockForUpdate` for the full ~100-250ms hash,
  pinning a database connection per in-flight request — a burst could exhaust
  the pool and take down the whole application. Single use is now guaranteed by
  compare-and-delete instead, with no lock and no transaction.
- **Failed-guess bookkeeping is no longer inside the package's transaction**, so
  the per-code `attempts` budget survives where it previously could not. See the
  README's consumer-transaction caveat for the residual you still own.
- **Both rate-limiter gates are atomic** (increment-then-compare). They were
  check-then-hit, so a concurrent burst passed the gate wholesale — 200
  simultaneous resends sent ~200 emails against a limit of 3.
- **A successful verify now refunds one unit instead of resetting the budget.**
  The reset was an attacker primitive: anyone able to produce one success could
  zero a nearly-exhausted counter and keep guessing.
- **The `Expired` failure path now costs the same bcrypt work as the others**, so
  response time no longer reveals that a recently-expired code exists.
- **A code issued after a successful consume is no longer swept**, so a resend
  landing in that window is not silently destroyed.
- **Deterministic row selection** (`latest('id')`) when two codes briefly coexist.

**Behavioral changes to be aware of when upgrading**

- The verify limiter now counts **every attempt**, not only failures; a
  successful attempt is refunded, so legitimate users are net-zero.
- `IssuedOtp` now **throws** on `serialize()` rather than masking. If you were
  passing the object into a queued job or session, pass `$issued->code` instead
  — that was already writing the plaintext to durable storage.
- `OtpLimiter::clear()` is renamed `refund()` (one unit). A full reset is
  available as `reset()` for out-of-band use such as an admin forgiving a lockout.

## v0.1.1 — 2026-07-26

Post-release hardening (no API changes).

- CI now runs the full suite against MySQL 8 as well as sqlite, so the
  `lockForUpdate` consume path executes on an engine with real row locks
- The no-active-code path burns an equivalent bcrypt check, so response time
  no longer reveals whether a code is pending for a user
- `IssuedOtp` implements `JsonSerializable` and masks the code under
  `json_encode`, closing the JSON-normalizing-logger leak channel

## v0.1.0 — 2026-07-25

Initial release.

- `HasOtps` trait: `issueOtp` / `verifyOtp` / `consumeOtp`, purpose-scoped via
  consumer-supplied enums implementing `OtpPurpose`
- bcrypt-hashed storage, CSPRNG generation (6-digit floor), 10-minute default expiry
- Rate limiting on both ends (issue and verify) plus a per-code attempts budget
- Optional context binding — codes bound to the address they were sent to
- `OtpIssued` / `OtpVerified` / `OtpVerificationFailed` events (codes never in payloads)
- Polymorphic: works with uuid and bigint model keys
- `MassPrunable` cleanup
