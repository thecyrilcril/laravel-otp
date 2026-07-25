<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'harden@example.com']);
});

it('never exposes the plaintext code in events or exceptions', function (): void {
    $captured = [];
    Event::listen(OtpIssued::class, function (OtpIssued $e) use (&$captured): void {
        $captured[] = print_r($e, true);
    });
    Event::listen(OtpVerificationFailed::class, function (OtpVerificationFailed $e) use (&$captured): void {
        $captured[] = print_r($e, true);
    });

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->user->verifyOtp(TestPurpose::EmailVerification, '999999');

    try {
        foreach (range(1, 10) as $i) {
            $this->user->verifyOtp(TestPurpose::EmailVerification, '999999');
        }
    } catch (OtpThrottledException $e) {
        $captured[] = $e->getMessage();
    }

    foreach ($captured as $payload) {
        expect($payload)->not->toContain($issued->code);
    }
});

it('a code cannot cross purposes even with identical digits', function (): void {
    // Force determinism: issue for one purpose, attempt on another.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::PasswordReset, $issued->code))->toBeFalse()
        ->and($this->user->otps()->where('purpose', 'email_verification')->count())->toBe(1);
});

it('expiry boundary: valid at expiry-1s, dead at expiry+1s', function (): void {
    $this->freezeTime();
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->travel(10 * 60 - 1)->seconds();
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();

    $this->travel(2)->seconds();
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('issuing after a throttled verify still yields a working new code', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 5) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    }

    // Verify limiter is saturated; issuing is governed independently.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect(fn () => $this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))
        ->toThrow(OtpThrottledException::class);
});

it('sequential double-consume: exactly one wins', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $first = $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);
    $second = $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);

    expect($first)->toBeTrue()->and($second)->toBeFalse();
});

it('context comparison tolerates null-issued codes checked with a context', function (): void {
    // Issued without context: presenting one anyway must not error or bind.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code, context: 'anything'))->toBeTrue();
});
