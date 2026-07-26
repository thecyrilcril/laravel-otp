<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

use Carbon\CarbonImmutable;
use JsonSerializable;
use LogicException;
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
     * Refuse serialization outright rather than masking it.
     *
     * serialize() is how queued job and notification payloads, and the file
     * and database session/cache drivers, encode objects — so a serialized
     * IssuedOtp writes the plaintext code into durable storage, defeating the
     * package's bcrypt-at-rest guarantee for the code's whole live window.
     *
     * Masking here would be worse than throwing: it would silently produce an
     * IssuedOtp whose ->code is '******' on the far side, turning a security
     * mistake into a baffling functional bug. Read ->code in the request that
     * issued it, hand it to your notification, and let the object go.
     *
     * @return array<string, mixed>
     *
     * @throws LogicException always
     */
    public function __serialize(): array
    {
        throw new LogicException(
            'IssuedOtp must not be serialized — read ->code immediately and discard the object. '
            .'Serializing it would write the plaintext OTP into queue payloads, sessions, or cache.'
        );
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
