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

it('throttles verification after the configured failures and clears on demand', function (): void {
    foreach (range(1, 5) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
        $this->limiter->recordFailure($this->user, TestPurpose::EmailVerification);
    }

    expect(fn () => $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);

    $this->limiter->clear($this->user, TestPurpose::EmailVerification);
    $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    expect(true)->toBeTrue();
});

it('guardVerify alone never records attempts', function (): void {
    // Called far past the limit with no recordFailure: must never throw,
    // proving guardVerify checks without recording.
    foreach (range(1, 10) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    }

    expect(true)->toBeTrue();
});
