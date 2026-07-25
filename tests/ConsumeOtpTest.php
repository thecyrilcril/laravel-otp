<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpVerified;
use Thecyrilcril\Otp\Tests\Fixtures\IntUser;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'consume@example.com']);
});

it('consumes a correct code exactly once', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue()
        ->and($this->user->otps()->count())->toBe(0);

    // Replay: the code is gone.
    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('fires OtpVerified on successful consumption', function (): void {
    Event::fake([OtpVerified::class]);

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);

    Event::assertDispatched(OtpVerified::class, fn (OtpVerified $e): bool => $e->otpable->is($this->user)
        && $e->purpose === TestPurpose::EmailVerification);
});

it('does not consume on a wrong code', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, '000000'))->toBeFalse()
        ->and($this->user->otps()->count())->toBe(1)
        ->and($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});

it('enforces context binding on consumption', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->consumeOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000'))->toBeFalse()
        ->and($this->user->consumeOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2348012345678'))->toBeTrue();
});

it('works identically on a bigint-keyed parent', function (): void {
    $intUser = IntUser::create(['email' => 'int@example.com']);

    $issued = $intUser->issueOtp(TestPurpose::EmailVerification);

    expect($intUser->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});
