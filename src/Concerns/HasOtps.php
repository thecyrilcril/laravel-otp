<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\DB;
use Thecyrilcril\Otp\Contracts\OtpPurpose;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\IssuedOtp;
use Thecyrilcril\Otp\Models\Otp;
use Thecyrilcril\Otp\Support\CodeGenerator;
use Thecyrilcril\Otp\Support\OtpLimiter;

trait HasOtps
{
    /**
     * @return MorphMany<Otp, $this>
     */
    public function otps(): MorphMany
    {
        return $this->morphMany(Otp::class, 'otpable');
    }

    /**
     * Issue a fresh code for the purpose, replacing any existing one.
     *
     * Returns the plaintext exactly once, for the consumer's own notification.
     * Never store or log the returned code.
     *
     * @throws OtpThrottledException
     * @throws \InvalidArgumentException when the configured length is below 6
     */
    public function issueOtp(OtpPurpose $purpose, ?string $context = null): IssuedOtp
    {
        app(OtpLimiter::class)->guardIssue($this, $purpose);

        $code = app(CodeGenerator::class)->generate(config()->integer('otp.length', 6));
        $expiresAt = CarbonImmutable::now()->addMinutes(config()->integer('otp.expires_after', 10));

        DB::transaction(function () use ($purpose, $code, $context, $expiresAt): void {
            $this->otps()->where('purpose', $purpose->value())->delete();

            $this->otps()->create([
                'purpose' => $purpose->value(),
                'code' => $code,
                'context' => $context,
                'expires_at' => $expiresAt,
            ]);
        });

        event(new OtpIssued($this, $purpose));

        return new IssuedOtp($code, $expiresAt);
    }
}
