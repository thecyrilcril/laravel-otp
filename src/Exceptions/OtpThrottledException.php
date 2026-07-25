<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Exceptions;

use RuntimeException;

final class OtpThrottledException extends RuntimeException
{
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct(sprintf('Too many OTP attempts. Retry in %d seconds.', $retryAfterSeconds));
    }

    public static function retryIn(int $seconds): self
    {
        return new self($seconds);
    }
}
