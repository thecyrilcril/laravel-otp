# Changelog

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
