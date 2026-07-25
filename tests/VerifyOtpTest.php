<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\FailureReason;
use Thecyrilcril\Otp\Support\OtpLimiter;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'verify@example.com']);
});

it('verifies a correct code without consuming it', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue()
        ->and($this->user->otps()->count())->toBe(1);

    // Repeatable while un-consumed.
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});

it('returns bare false for every failure mode', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    // Wrong code / wrong purpose / wrong context / no row at all — all identical to the caller.
    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, '000000', context: '+2348012345678'))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000'))->toBeFalse();
});

it('rejects an expired code', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->travel(11)->minutes();

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('binds a code to its issued context', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    // Phone A → verify with phone B fails; with A succeeds.
    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2349999999999'))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2348012345678'))->toBeTrue();
});

it('requires the context when one was issued, even if omitted at verify time', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code))->toBeFalse();
});

it('fires precise failure events while the caller sees only false', function (): void {
    Event::fake([OtpVerificationFailed::class]);

    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    $this->user->verifyOtp(TestPurpose::PhoneVerification, '000000', context: '+2348012345678');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::CodeMismatch);

    $this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::ContextMismatch);

    $this->user->verifyOtp(TestPurpose::PasswordReset, '000000');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::NotFound);
});

it('kills the code after max_attempts failures, independent of the limiter window', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 4) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
        // Reset the limiter each round to prove the per-row counter acts alone.
        app(OtpLimiter::class)->clear($this->user, TestPurpose::EmailVerification);
    }

    // 5th failure deletes the row.
    $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    app(OtpLimiter::class)->clear($this->user, TestPurpose::EmailVerification);

    expect($this->user->otps()->count())->toBe(0)
        ->and($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('throttles verification attempts past the limit', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 5) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    }

    expect(fn () => $this->user->verifyOtp(TestPurpose::EmailVerification, '000000'))
        ->toThrow(OtpThrottledException::class);
});

it('emits Expired as the failure reason for an expired code, even when the code is correct', function (): void {
    Event::fake([OtpVerificationFailed::class]);

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->travel(11)->minutes();

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();

    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::Expired);
});
