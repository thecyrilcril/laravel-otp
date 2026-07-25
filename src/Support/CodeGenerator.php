<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Support;

use InvalidArgumentException;

final class CodeGenerator
{
    private const int MINIMUM_LENGTH = 6;

    private const int MAXIMUM_LENGTH = 10;

    /**
     * Generate a cryptographically random, zero-padded numeric code.
     */
    public function generate(int $length): string
    {
        if ($length < self::MINIMUM_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('OTP length must be at least %d digits, %d configured.', self::MINIMUM_LENGTH, $length)
            );
        }

        if ($length > self::MAXIMUM_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('OTP length must be at most %d digits, %d configured.', self::MAXIMUM_LENGTH, $length)
            );
        }

        $max = (10 ** $length) - 1;

        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }
}
