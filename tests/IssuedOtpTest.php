<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Thecyrilcril\Otp\IssuedOtp;

it('exposes the code and expiry', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    expect($issued->code)->toBe('123456')
        ->and($issued->expiresAt)->toBeInstanceOf(CarbonImmutable::class);
});

it('masks the code in debug output', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    $dump = print_r($issued->__debugInfo(), true);

    expect($dump)->not->toContain('123456')
        ->and($dump)->toContain('******');
});

it('masks the code under json_encode', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    $json = json_encode($issued, JSON_THROW_ON_ERROR);

    expect($json)->not->toContain('123456')
        ->and($json)->toContain('******');
});

it('refuses to be serialized rather than leaking the code into durable storage', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    expect(fn (): string => serialize($issued))
        ->toThrow(LogicException::class, 'must not be serialized');
});

it('still exposes the code directly — the object must remain usable', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    expect($issued->code)->toBe('123456');
});
