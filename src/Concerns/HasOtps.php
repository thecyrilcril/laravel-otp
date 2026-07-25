<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use SensitiveParameter;
use Thecyrilcril\Otp\Contracts\OtpPurpose;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Events\OtpVerified;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\FailureReason;
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

    /**
     * Check a code without consuming it. Non-destructive on success — but a
     * failed check still counts against the rate limiter and the per-row
     * attempts budget, or this would be a counter-free brute-force channel.
     *
     * @throws OtpThrottledException
     */
    public function verifyOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context = null): bool
    {
        return $this->checkOtp($purpose, $code, $context, consume: false);
    }

    /**
     * Check a code and, on success, delete it atomically (single use).
     *
     * @throws OtpThrottledException
     */
    public function consumeOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context = null): bool
    {
        return $this->checkOtp($purpose, $code, $context, consume: true);
    }

    private function checkOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context, bool $consume): bool
    {
        $limiter = app(OtpLimiter::class);

        try {
            $limiter->guardVerify($this, $purpose);
        } catch (OtpThrottledException $e) {
            event(new OtpVerificationFailed($this, $purpose, FailureReason::Throttled));

            throw $e;
        }

        return DB::transaction(function () use ($purpose, $code, $context, $consume, $limiter): bool {
            /** @var Otp|null $otp */
            $otp = $this->otps()
                ->where('purpose', $purpose->value())
                ->lockForUpdate()
                ->first();

            $reason = $this->failureReasonFor($otp, $code, $context);

            if ($reason instanceof FailureReason) {
                $this->recordFailure($otp, $purpose, $reason, $limiter);

                return false;
            }

            /** @var Otp $otp known non-null: failureReasonFor returned null */
            if ($consume) {
                $otp->delete();
            }

            $limiter->clear($this, $purpose);
            event(new OtpVerified($this, $purpose));

            return true;
        });
    }

    private function failureReasonFor(?Otp $otp, #[SensitiveParameter] string $code, ?string $context): ?FailureReason
    {
        if (! $otp instanceof Otp) {
            return FailureReason::NotFound;
        }

        if ($otp->isExpired()) {
            return FailureReason::Expired;
        }

        if (! Hash::check($code, $otp->getRawOriginal('code'))) {
            return FailureReason::CodeMismatch;
        }

        if ($otp->context !== null && ! hash_equals($otp->context, (string) $context)) {
            return FailureReason::ContextMismatch;
        }

        return null;
    }

    private function recordFailure(?Otp $otp, OtpPurpose $purpose, FailureReason $reason, OtpLimiter $limiter): void
    {
        $limiter->recordFailure($this, $purpose);

        if ($otp instanceof Otp) {
            $otp->increment('attempts');

            if ($otp->attempts >= config()->integer('otp.max_attempts', 5)) {
                $otp->delete();
            }
        }

        event(new OtpVerificationFailed($this, $purpose, $reason));
    }
}
