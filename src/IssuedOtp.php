<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * The one-time exposure of a plaintext OTP code. Returned by issueOtp() so the
 * consumer can hand the code to its own notification; never persisted, never
 * logged (debug output masks it).
 */
final readonly class IssuedOtp
{
    public function __construct(
        #[SensitiveParameter] public string $code,
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'code' => '******',
            'expiresAt' => $this->expiresAt->toIso8601String(),
        ];
    }
}
