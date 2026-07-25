<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Support;

use InvalidArgumentException;

final class CodeGenerator
{
    private const int MINIMUM_LENGTH = 6;

    /**
     * Lengths of 19 or more make `10 ** $length` overflow int into a float,
     * and passing a float max to `random_int()` throws a TypeError. 10 is
     * chosen safely below that overflow point, with margin to spare. (It
     * also carries no security benefit past 10 — see the README — but the
     * overflow is the reason this is a hard ceiling rather than a
     * recommendation.)
     */
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
