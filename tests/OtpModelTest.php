<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Thecyrilcril\Otp\Models\Otp;
use Thecyrilcril\Otp\Tests\Fixtures\IntUser;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

it('stores the code hashed, never plaintext', function (): void {
    $user = UuidUser::create(['email' => 'a@example.com']);

    $otp = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '123456',
        'expires_at' => now()->addMinutes(10),
    ]);

    $raw = $otp->getRawOriginal('code');

    expect($raw)->not->toBe('123456')
        ->and(Hash::check('123456', $raw))->toBeTrue();
});

it('morphs to uuid-keyed and bigint-keyed parents', function (): void {
    $uuidUser = UuidUser::create(['email' => 'u@example.com']);
    $intUser = IntUser::create(['email' => 'i@example.com']);

    $a = $uuidUser->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '111111',
        'expires_at' => now()->addMinutes(10),
    ]);
    $b = $intUser->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '222222',
        'expires_at' => now()->addMinutes(10),
    ]);

    expect($a->otpable)->toBeInstanceOf(UuidUser::class)
        ->and($a->otpable->getKey())->toBe($uuidUser->getKey())
        ->and($b->otpable)->toBeInstanceOf(IntUser::class)
        ->and($b->otpable->getKey())->toBe($intUser->getKey());
});

it('knows whether it is expired', function (): void {
    $user = UuidUser::create(['email' => 'e@example.com']);

    $live = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '123456',
        'expires_at' => now()->addMinute(),
    ]);
    $dead = $user->otps()->create([
        'purpose' => TestPurpose::PasswordReset->value,
        'code' => '123456',
        'expires_at' => now()->subSecond(),
    ]);

    expect($live->isExpired())->toBeFalse()
        ->and($dead->isExpired())->toBeTrue();
});

it('prunes only expired rows', function (): void {
    $user = UuidUser::create(['email' => 'p@example.com']);

    $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '111111',
        'expires_at' => now()->subMinute(),
    ]);
    $user->otps()->create([
        'purpose' => TestPurpose::PasswordReset->value,
        'code' => '222222',
        'expires_at' => now()->addMinutes(10),
    ]);

    $pruned = (new Otp)->prunable()->count();

    expect($pruned)->toBe(1);
});

it('accepts any backed string enum through the contract', function (): void {
    expect(TestPurpose::EmailVerification->value())->toBe('email_verification')
        ->and(TestPurpose::PhoneVerification->value())->toBe('phone_verification');
});
