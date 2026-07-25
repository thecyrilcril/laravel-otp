<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

use Carbon\CarbonImmutable;
use JsonSerializable;
use SensitiveParameter;

/**
 * The one-time exposure of a plaintext OTP code. Returned by issueOtp() so the
 * consumer can hand the code to its own notification; never persisted, never
 * logged — both debug output and JSON serialization mask the code, so an
 * accidental `Log::info('...', ['otp' => $issued])` through a JSON-normalizing
 * logger cannot leak it either.
 */
final readonly class IssuedOtp implements JsonSerializable
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
        return $this->masked();
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->masked();
    }

    /**
     * @return array<string, string>
     */
    private function masked(): array
    {
        return [
            'code' => '******',
            'expiresAt' => $this->expiresAt->toIso8601String(),
        ];
    }
}
