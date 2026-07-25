<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Tests\Fixtures;

use Thecyrilcril\Otp\Contracts\OtpPurpose;

enum TestPurpose: string implements OtpPurpose
{
    case EmailVerification = 'email_verification';
    case PasswordReset = 'password_reset';
    case PhoneVerification = 'phone_verification';

    public function value(): string
    {
        return $this->value;
    }
}
