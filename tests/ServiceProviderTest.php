<?php

declare(strict_types=1);

it('boots and merges the otp config', function (): void {
    expect(config('otp.length'))->toBe(6)
        ->and(config('otp.expires_after'))->toBe(10)
        ->and(config('otp.verify_limit'))->toBe(['attempts' => 5, 'decay' => 60])
        ->and(config('otp.issue_limit'))->toBe(['attempts' => 3, 'decay' => 600])
        ->and(config('otp.max_attempts'))->toBe(5)
        ->and(config('otp.table'))->toBe('otps');
});
