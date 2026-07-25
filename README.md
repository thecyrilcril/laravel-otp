# Laravel OTP

Purpose-scoped, hashed, rate-limited one-time passwords for Laravel.

[![Tests](https://github.com/thecyrilcril/laravel-otp/actions/workflows/ci.yml/badge.svg)](https://github.com/thecyrilcril/laravel-otp/actions/workflows/ci.yml)
[![Latest Version](https://img.shields.io/packagist/v/thecyrilcril/laravel-otp.svg)](https://packagist.org/packages/thecyrilcril/laravel-otp)
[![License](https://img.shields.io/packagist/l/thecyrilcril/laravel-otp.svg)](https://packagist.org/packages/thecyrilcril/laravel-otp)

## What it is

Laravel OTP adds one-time-password verification to any Eloquent model: codes are
purpose-scoped (an email-verification code can never satisfy a password-reset check),
hashed at rest, rate-limited on both the issuing and the verifying side, and single-use
when consumed. It was extracted from two hand-rolled implementations that had been running
in production without those controls, and hardened with the gaps both were missing —
bcrypt storage instead of reversible encryption, and rate limiting on top of a bare
attempts counter. It does not send anything: you keep your own notification classes, and
the package hands you the plaintext code exactly once so you can pass it along.

It exists because nothing on Packagist covers all three properties this package requires
at once: `spatie/laravel-one-time-passwords` stores codes in plaintext with no purpose
scoping, `otpz` has no concept of purposes, and `otpify` has no rate limiting.

## Install

```bash
composer require thecyrilcril/laravel-otp
php artisan vendor:publish --tag=otp-migrations
php artisan vendor:publish --tag=otp-config   # optional
php artisan migrate
```

The published migration is forward-only (no `down()`), so `php artisan migrate:rollback`
will not drop the `otps` table.

The config publish is optional — every setting has a sensible default (see
[Configuration](#configuration) below). Publish it only if you need to change a limit,
the expiry window, or the code length.

## Setup

Define a purpose enum implementing `OtpPurpose`, then add the `HasOtps` trait to whichever
model will issue and verify codes (typically your `User` model, but any Eloquent model
works — the relationship is polymorphic):

```php
use Thecyrilcril\Otp\Contracts\OtpPurpose;

enum Purpose: string implements OtpPurpose
{
    case EmailVerification = 'email_verification';
    case PhoneVerification = 'phone_verification';

    public function value(): string
    {
        return $this->value;
    }
}

// On the model:
use Thecyrilcril\Otp\Concerns\HasOtps;

final class User extends Authenticatable
{
    use HasOtps;
}
```

The enum's `value()` is stored in the `purpose` column and scopes every operation — a code
issued for one purpose can never satisfy a check against another.

## Usage

### Issuing a code

```php
$issued = $user->issueOtp(Purpose::EmailVerification);

$issued->code;      // the plaintext, available exactly once
$issued->expiresAt; // CarbonImmutable
```

`issueOtp()` never sends anything. Feed `$issued->code` into your own notification (Mail,
SMS gateway, whatever). The package's involvement ends the moment it returns the code —
it is not stored anywhere in plaintext, and `IssuedOtp`'s debug output masks it, so a
stray `dump($issued)` in a log won't leak it.

Issuing a new code for a purpose deletes any existing, unconsumed code for that same
purpose first — there is only ever one live code per model+purpose pair.

### Verifying vs. consuming

```php
$user->verifyOtp(Purpose::EmailVerification, $code);   // check only, code survives
$user->consumeOtp(Purpose::EmailVerification, $code);   // check + delete, single-use
```

Both return `bool`. Use `verifyOtp()` when you need to check a code without spending it
(for example, a multi-step form where the user might need to resubmit); use
`consumeOtp()` for anything security-sensitive, since it deletes the row atomically on
success so the same code can never be replayed. A failed check still counts against the
rate limiter and the per-code attempts budget either way — `verifyOtp()` is
non-destructive on *success* only, not a free-to-guess channel.

### Context binding

Pass `context` when issuing and again when verifying to bind a code to the value it was
sent to:

```php
$user->issueOtp(Purpose::PhoneVerification, context: '+2348012345678');
$user->consumeOtp(Purpose::PhoneVerification, $code, context: $submittedPhone);
```

This closes a change-of-target hole: without it, a user could request a code for phone A,
edit the pending phone number to B, then submit the code they received on A — and B would
end up verified having never received anything. Binding the code to the address it was
actually sent to means a code sent to A only ever satisfies a check against A.

Omit `context` for purposes with no target to bind, such as a login-time 2FA check:

```php
$user->issueOtp(Purpose::TwoFactorLogin);
```

### Handling throttling

Both issuing and verifying are rate-limited. Either can throw:

```php
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;

try {
    $user->issueOtp(Purpose::EmailVerification);
} catch (OtpThrottledException $e) {
    // $e->retryAfterSeconds — seconds until the limit resets
}
```

## Security model

| Control | Detail |
|---|---|
| Hashed at rest | Codes are stored via Eloquent's `hashed` (bcrypt) cast — a leaked database yields no usable codes. |
| Verification order | Rate limit → row lookup → expiry → `Hash::check` → context `hash_equals`. The limiter runs first, so a brute-forcer cannot even trigger bcrypt work once throttled. |
| Both-ends rate limiting | Issuing is throttled (stops mail/SMS bombing and DoS-by-regeneration against a victim); verifying is throttled separately (stops brute force). |
| Per-code attempts budget | A per-row failure counter kills a code outright after too many wrong guesses, even if the rate-limit window has already rolled over. |
| Single-use | `consumeOtp()` checks and deletes in one `DB::transaction` with a row lock — two simultaneous submissions of the same code cannot both succeed. |
| Enumeration-resistant | Every failure path — missing row, expired, wrong code, wrong context, throttled — returns the same `false` to the caller. The precise reason is only ever visible internally, via the failure event. |
| Context binding | Optional target binding (see above) closes the change-of-target attack that plain code verification is otherwise silent to. |
| Secrets hygiene | Code parameters are marked `#[SensitiveParameter]` throughout, and `IssuedOtp` masks the code in its `__debugInfo()`. |

## Events

Three events are dispatched over the lifecycle, none of which ever carry a plaintext code:

- `OtpIssued` — fired after a code is generated and stored. Carries the `otpable` model and
  the `purpose`.
- `OtpVerified` — fired when `verifyOtp()` or `consumeOtp()` succeeds. Carries the
  `otpable` model and the `purpose`.
- `OtpVerificationFailed` — fired on any failed check, including throttled attempts.
  Carries the `otpable` model, the `purpose`, and a `reason` (`FailureReason` enum):
  `NotFound`, `Expired`, `CodeMismatch`, `ContextMismatch`, or `Throttled`.

The failure reason is only ever available to your own listeners — the boolean the caller
gets back from `verifyOtp()`/`consumeOtp()` never reveals which of these it was, to avoid
giving an attacker a signal to enumerate against.

## Configuration

Publish the config with `php artisan vendor:publish --tag=otp-config` to override any of
these defaults:

```php
'length'        => 6,   // digits; must be between 6 and 10 inclusive
'expires_after' => 10,  // minutes
'verify_limit'  => ['attempts' => 5, 'decay' => 60],    // per model+purpose
'issue_limit'   => ['attempts' => 3, 'decay' => 600],   // per model+purpose
'max_attempts'  => 5,   // per-code failure budget
'table'         => 'otps',
```

`length` is bounds-checked at runtime: configuring fewer than 6 digits throws an
`InvalidArgumentException` because a shorter numeric code is brute-forceable even through
the rate limiter, and configuring more than 10 digits throws for the same reason in
reverse — there's no security benefit past 10, and it's almost certainly a
misconfiguration.

## Scheduling cleanup

Expired codes are cleaned up via Laravel's `MassPrunable`. Schedule the prune command:

```php
$schedule->command('model:prune', ['--model' => [\Thecyrilcril\Otp\Models\Otp::class]])->daily();
```

## Migration guide sketch

If you're migrating off a hand-rolled OTP trait shaped like the ones this package was
extracted from:

- `sendEmailVerificationOtp()`-style methods map onto `issueOtp(...)` plus your own
  existing notification call — the package never sends anything, so your notification
  class doesn't change.
- `verifyOtp(purpose, code)` keeps the same name and shape, but the stored codes are now
  bcrypt hashes rather than plaintext or encrypted values. Existing rows from the old
  implementation cannot be migrated forward — hashing is one-way — so expire or delete
  them and have affected users request a fresh code after upgrading.
- Both rate limits (issue-side and verify-side) come for free the moment the trait is in
  place; if your hand-rolled version had no throttling, or only a bare attempts counter,
  this closes that gap without any extra work on your part.

## Versioning note

This package is on `0.x` until the first real consumer migration proves the API surface
in production. Breaking changes are possible before `1.0`.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
