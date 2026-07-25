<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\IssuedOtp;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'issue@example.com']);
});

it('issues a hashed code and returns the plaintext once', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($issued)->toBeInstanceOf(IssuedOtp::class)
        ->and(strlen($issued->code))->toBe(6)
        ->and(ctype_digit($issued->code))->toBeTrue();

    $row = $this->user->otps()->sole();

    expect($row->purpose)->toBe('email_verification')
        ->and($row->getRawOriginal('code'))->not->toBe($issued->code)
        ->and(Hash::check($issued->code, $row->getRawOriginal('code')))->toBeTrue()
        ->and($row->context)->toBeNull()
        ->and($row->attempts)->toBe(0);
});

it('sets expiry from config', function (): void {
    $this->freezeTime();

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($issued->expiresAt->timestamp)->toBe(now()->addMinutes(10)->timestamp);
});

it('stores the context when given', function (): void {
    $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->otps()->sole()->context)->toBe('+2348012345678');
});

it('replaces any existing code for the same purpose', function (): void {
    $first = $this->user->issueOtp(TestPurpose::EmailVerification);
    $second = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->otps()->count())->toBe(1)
        ->and(Hash::check($second->code, $this->user->otps()->sole()->getRawOriginal('code')))->toBeTrue()
        ->and(Hash::check($first->code, $this->user->otps()->sole()->getRawOriginal('code')))->toBeFalse();
});

it('keeps codes for different purposes independent', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->user->issueOtp(TestPurpose::PasswordReset);

    expect($this->user->otps()->count())->toBe(2);
});

it('fires OtpIssued without leaking the code', function (): void {
    Event::fake([OtpIssued::class]);

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    Event::assertDispatched(OtpIssued::class, function (OtpIssued $event) use ($issued): bool {
        return $event->otpable->is($this->user)
            && $event->purpose === TestPurpose::EmailVerification
            && ! str_contains(print_r($event, true), $issued->code);
    });
});

it('throttles issuance past the configured limit', function (): void {
    foreach (range(1, 3) as $i) {
        $this->user->issueOtp(TestPurpose::EmailVerification);
    }

    expect(fn () => $this->user->issueOtp(TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);
});

it('rejects a code length configured below six', function (): void {
    config()->set('otp.length', 4);

    expect(fn () => $this->user->issueOtp(TestPurpose::EmailVerification))
        ->toThrow(InvalidArgumentException::class);
});
