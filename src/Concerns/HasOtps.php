<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Concerns;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Thecyrilcril\Otp\Models\Otp;

trait HasOtps
{
    /**
     * @return MorphMany<Otp, $this>
     */
    public function otps(): MorphMany
    {
        return $this->morphMany(Otp::class, 'otpable');
    }
}
