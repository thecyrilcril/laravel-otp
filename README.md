# Laravel OTP

Purpose-scoped, hashed, rate-limited one-time passwords for Laravel.

[![Tests](https://github.com/thecyrilcril/laravel-otp/actions/workflows/ci.yml/badge.svg)](https://github.com/thecyrilcril/laravel-otp/actions/workflows/ci.yml)
[![Latest Version](https://img.shields.io/packagist/v/thecyrilcril/laravel-otp.svg)](https://packagist.org/packages/thecyrilcril/laravel-otp)
[![License](https://img.shields.io/packagist/l/thecyrilcril/laravel-otp.svg)](https://packagist.org/packages/thecyrilcril/laravel-otp)

## What it is

This package adds one-time-password (OTP) verification to any Eloquent model. An OTP is
a short numeric code — the kind sent to verify an email address, a phone number, or a
login attempt.

Four properties make it safe to use in production:

1. **Purpose-scoped.** Every code is issued for a specific purpose (`EmailVerification`,
   `PasswordReset`, and so on). A code issued for one purpose can never satisfy a check
   for a different purpose, even if the digits happen to match.
2. **Hashed at rest.** Codes are never stored as plain text — they're stored as bcrypt
   hashes, the same one-way scrambling used for passwords. A leaked database yields no
   usable codes.
3. **Rate-limited on both ends.** Issuing new codes is throttled (so nobody can spam a
   victim's inbox), and verifying codes is throttled separately (so nobody can brute-force
   a guess).
4. **Single-use.** Once a code is successfully consumed, it's deleted. It can never be
   replayed.

The package was extracted from two hand-rolled OTP implementations that had been running
in production without these controls, and hardened with what both were missing: bcrypt
storage instead of reversible encryption, and rate limiting on top of a bare attempts
counter.

**One thing it deliberately does not do: send anything.** `issueOtp()` hands you the
plaintext code exactly once. You write your own notification class to email it, text it,
or deliver it however you like — see [the example further down](#sending-the-code-a-worked-example)
for exactly how to wire that up.

It exists because nothing else on Packagist covers all three of purpose-scoping, hashing,
and rate limiting at once: `spatie/laravel-one-time-passwords` stores codes in plaintext
with no purpose scoping, `otpz` has no concept of purposes, and `otpify` has no rate
limiting.

## Install

```bash
composer require thecyrilcril/laravel-otp
php artisan vendor:publish --tag=otp-migrations
php artisan vendor:publish --tag=otp-config   # optional
php artisan migrate
```

The published migration is forward-only — it has no `down()` method — so
`php artisan migrate:rollback` will not drop the `otps` table.

The config publish is optional. Every setting has a sensible default; see
[Configuration](#configuration) below. Publish it only if you need to change a limit, the
expiry window, or the code length.

## Setup

Two steps.

**1. Define a purpose enum implementing `OtpPurpose`.** This is what scopes every code to
what it's actually for:

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
```

**2. Add the `HasOtps` trait** to whichever model will issue and verify codes — typically
your `User` model, but any Eloquent model works, since the relationship is polymorphic:

```php
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

`issueOtp()` never sends anything. It only creates the code and hands it back to you.
Feed `$issued->code` into your own notification — see the
[worked example below](#sending-the-code-a-worked-example).

The package's involvement ends the moment it returns the code. That code is not stored
anywhere in plaintext, and `IssuedOtp` masks it in both debug output and JSON
serialization — so neither a stray `dump($issued)` nor a JSON-normalizing logger
(`Log::info('...', ['otp' => $issued])`) will leak it.

Issuing a new code for a purpose deletes any existing, unconsumed code for that same
purpose first. There is only ever one live code per model+purpose pair.

### Verifying vs. consuming

```php
$user->verifyOtp(Purpose::EmailVerification, $code);   // check only, code survives
$user->consumeOtp(Purpose::EmailVerification, $code);  // check + delete, single-use
```

Both return `bool`.

- Use **`verifyOtp()`** when you need to check a code without spending it — for example, a
  multi-step form where the user might need to resubmit.
- Use **`consumeOtp()`** for anything security-sensitive. It deletes the row atomically on
  success, so the same code can never be replayed.

**Every** attempt — right or wrong — counts against the rate limiter. A successful attempt
is refunded a single unit, so legitimate users are net-zero. Every *failed* attempt
additionally charges the per-code attempts budget. `verifyOtp()` is non-destructive on
*success* only — it is not a free-to-guess channel.

### Context binding

Pass `context` when issuing and again when verifying to bind a code to the value it was
sent to:

```php
$user->issueOtp(Purpose::PhoneVerification, context: '+2348012345678');
$user->consumeOtp(Purpose::PhoneVerification, $code, context: $submittedPhone);
```

This closes a change-of-target hole. Without it, a user could request a code for phone A,
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

## Sending the code: a worked example

The package hands you the plaintext code once. It never sends it. Here is a complete,
copy-pasteable notification you can drop into your project and adjust:

```php
<?php

declare(strict_types=1);

namespace App\Notifications;

use Carbon\CarbonImmutable;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use SensitiveParameter;

final class SendOtpCode extends Notification implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public function __construct(
        #[SensitiveParameter]
        private readonly string $code,
        private readonly CarbonImmutable $expiresAt,
    ) {}

    /** @return list<string> */
    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): MailMessage
    {
        $minutes = (int) max(1, round(now()->diffInMinutes($this->expiresAt)));

        return new MailMessage()
            ->subject('Your verification code')
            ->line('Use the code below to verify your account.')
            ->line("**{$this->code}**")
            ->line("This code expires in {$minutes} minute(s).")
            ->line("If you didn't request this, you can safely ignore this email.");
    }
}
```

Use it right after issuing a code:

```php
$issued = $user->issueOtp(Purpose::EmailVerification);

$user->notify(new SendOtpCode($issued->code, $issued->expiresAt));
```

Two details in that class matter beyond boilerplate:

- **`ShouldQueue`** sends the notification on the queue instead of blocking the request —
  standard practice for anything that talks to an external mail or SMS provider.
- **`ShouldBeEncrypted`** is the one that's easy to skip and genuinely load-bearing. Queued
  notifications are serialized into the queue payload — often a database `jobs` table.
  Without `ShouldBeEncrypted`, the plaintext code would sit readable in that table for
  however long it takes the worker to process the job, defeating the package's
  bcrypt-at-rest guarantee before the code is even used. With it, Laravel encrypts the
  whole payload before it's persisted and only decrypts it right before dispatch.

Swap `via()`/`toMail()` for your SMS provider's channel if you're sending by text instead —
the `ShouldQueue` + `ShouldBeEncrypted` pair still applies either way.

## Security model

| Control | Detail |
|---|---|
| Hashed at rest | Codes are stored via Eloquent's `hashed` (bcrypt) cast — a leaked database yields no usable codes. |
| Verification order | Rate limit → row lookup → expiry → `Hash::check` → context `hash_equals`. The limiter runs first, so a brute-forcer cannot even trigger bcrypt work once throttled. |
| Both-ends rate limiting | Issuing is throttled (stops mail/SMS bombing and DoS-by-regeneration against a victim); verifying is throttled separately (stops brute force). Both limiter gates are atomic — a burst of concurrent requests cannot slip through a check-then-hit gap. |
| Per-code attempts budget | A per-row failure counter kills a code outright after too many wrong guesses, even if the rate-limit window has already rolled over. |
| Single-use, lock-free | `consumeOtp()` uses compare-and-delete (`WHERE id = ? AND attempts = ?`, checking `affected === 1`) rather than a row lock — two simultaneous submissions of the same code cannot both succeed, and no database connection is pinned while the bcrypt check runs. |
| Enumeration-resistant | Every failure path — missing row, expired, wrong code, wrong context, throttled — returns the same `false` to the caller, at the same cost (response timing is equalized across every branch). The precise reason is only ever visible internally, via the failure event. |
| Context binding | Optional target binding (see above) closes the change-of-target attack that plain code verification is otherwise silent to. |
| Secrets hygiene | Code parameters are marked `#[SensitiveParameter]` throughout; `IssuedOtp` masks the code in `__debugInfo()` and `jsonSerialize()`, and **throws** if you try to `serialize()` it (that is how queue payloads and file/database sessions encode objects — the one channel that would write the plaintext to durable storage). |

### ⚠️ Do not call `verifyOtp()`/`consumeOtp()` inside a transaction that rolls back

A failed check charges two budgets: the rate limiter (in the cache) and the per-code
`attempts` counter (a database row). The package deliberately runs the `attempts` write
outside any transaction of its own — but it **cannot escape a transaction you opened**. If
your code wraps the call and then throws to signal failure, your rollback takes the
`attempts` increment with it, and an attacker gets unlimited guesses against a live code
for its whole validity window.

```php
// ❌ the rollback erases the failed-guess record
DB::transaction(function () use ($user, $code) {
    if (! $user->consumeOtp(Purpose::EmailVerification, $code)) {
        throw ValidationException::withMessages([...]);   // attempts increment lost
    }
    $user->markEmailAsVerified();
});

// ✅ check outside; only the success path is transactional
$consumed = $user->consumeOtp(Purpose::EmailVerification, $code);

if (! $consumed) {
    throw ValidationException::withMessages([...]);
}

DB::transaction(fn () => $user->markEmailAsVerified());
```

The rate limiter is unaffected either way — it lives in the cache, not the database — so
throttling still applies. But the per-code budget is the backstop that survives a flushed
or per-server cache, and it's worth keeping intact.

## Events

Three events are dispatched over the lifecycle, none of which ever carry a plaintext code:

- `OtpIssued` — fired after a code is generated and stored. Carries the `otpable` model and
  the `purpose`.
- `OtpVerified` — fired when `verifyOtp()` or `consumeOtp()` succeeds. Carries the
  `otpable` model and the `purpose`.
- `OtpVerificationFailed` — fired on any failed check, including throttled attempts.
  Carries the `otpable` model, the `purpose`, and a `reason` (`FailureReason` enum):
  `NotFound`, `Expired`, `CodeMismatch`, `ContextMismatch`, or `Throttled`.

The failure reason is only ever available to your own listeners. The boolean the caller
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

`length` is bounds-checked at runtime. Configuring fewer than 6 digits throws an
`InvalidArgumentException`, because a shorter numeric code is brute-forceable even through
the rate limiter. Configuring more than 10 digits throws for the same reason in reverse —
there's no security benefit past 10, and it's almost certainly a misconfiguration.

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
  place. If your hand-rolled version had no throttling, or only a bare attempts counter,
  this closes that gap without any extra work on your part.
- **Check your cache store before relying on the limiters.** Both rate limiters live in
  your app's **default cache store**. On a single server any store works. On a
  multi-server deploy, a per-server store (`file`, `array`) gives each server its own
  counters — an attacker spraying requests across N servers gets roughly N× the
  configured limits. Use a shared store (`database`, `redis`, `memcached`) in that
  topology. The per-code `attempts` budget lives in the database row itself and holds
  regardless of cache topology — it is the backstop, not a replacement for a shared
  store.

## Versioning note

This package is on `0.x` until the first real consumer migration proves the API surface
in production. Breaking changes are possible before `1.0`.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
