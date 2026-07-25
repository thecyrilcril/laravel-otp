<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Thecyrilcril\Otp\Contracts\OtpPurpose;

final class OtpVerified
{
    use Dispatchable;

    public function __construct(
        public readonly Model $otpable,
        public readonly OtpPurpose $purpose,
    ) {}
}
