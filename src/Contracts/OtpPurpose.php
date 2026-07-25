<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Contracts;

/**
 * Implemented by consumer-supplied backed string enums. The returned value is
 * stored in the `purpose` column and scopes every OTP operation: a code issued
 * for one purpose can never satisfy a check for another.
 */
interface OtpPurpose
{
    public function value(): string;
}
