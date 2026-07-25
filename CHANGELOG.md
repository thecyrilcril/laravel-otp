# Changelog

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
