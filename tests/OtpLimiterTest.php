<?php

declare(strict_types=1);

use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\Support\OtpLimiter;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'limits@example.com']);
    $this->limiter = app(OtpLimiter::class);
});

it('allows issuance up to the limit then throttles with retry-after', function (): void {
    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    try {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
        $this->fail('Expected OtpThrottledException');
    } catch (OtpThrottledException $e) {
        expect($e->retryAfterSeconds)->toBeGreaterThan(0)
            ->and($e->retryAfterSeconds)->toBeLessThanOrEqual(600);
    }
});

it('scopes limits per purpose', function (): void {
    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    // Different purpose: unaffected.
    $this->limiter->guardIssue($this->user, TestPurpose::PasswordReset);
    expect(true)->toBeTrue();
});

it('scopes limits per user', function (): void {
    $other = UuidUser::create(['email' => 'other@example.com']);

    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    $this->limiter->guardIssue($other, TestPurpose::EmailVerification);
    expect(true)->toBeTrue();
});

it('throttles verification after the configured attempts and clears on demand', function (): void {
    foreach (range(1, 5) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    }

    expect(fn () => $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);

    $this->limiter->reset($this->user, TestPurpose::EmailVerification);
    $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    expect(true)->toBeTrue();
});

it('guardVerify is itself the gate: N calls past the limit throw with no recordFailure involved', function (): void {
    // `recordFailure()` no longer exists — guardVerify's own increment is
    // the only bookkeeping. 5 calls pass (the configured limit), the 6th
    // (and every call thereafter) throws, proving the gate is atomic and
    // self-contained: nothing external needs to "record" an attempt.
    foreach (range(1, 5) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    }

    foreach (range(1, 3) as $i) {
        expect(fn () => $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification))
            ->toThrow(OtpThrottledException::class);
    }
});

it('refund() gives back exactly one unit and is not a budget reset', function (): void {
    // A legitimate user's successful verify is net-zero: charge one, refund
    // one, repeatable forever — this is the common case and must never throw.
    foreach (range(1, 50) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
        $this->limiter->refund($this->user, TestPurpose::EmailVerification);
    }

    // Now saturate the counter to its ceiling (5) with real charges that are
    // NEVER refunded (simulating wrong guesses), then refund ONCE (simulating
    // the one successful attempt in a "4 wrong then 1 correct" loop). A
    // correct, bounded refund puts the budget at 4/5: exactly one more
    // guarded call is allowed before throttling kicks in again. A full-reset
    // refund (the old `clear()` behavior) would instead let this loop repeat
    // forever within the same window — the exact vulnerability this test
    // exists to close.
    foreach (range(1, 5) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    }

    $this->limiter->refund($this->user, TestPurpose::EmailVerification);

    // Budget is at 4/5: exactly one more guarded call is allowed...
    $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);

    // ...and the next one throttles again.
    expect(fn () => $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);
});
