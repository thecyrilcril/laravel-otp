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
     * @throws \InvalidArgumentException when the configured length is outside the 6–10 bounds
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

        // Unlocked read, newest row first: no lock is held while bcrypt runs
        // below (a pinned connection per in-flight verify is an availability
        // vector), and when two concurrently-issued rows exist the check
        // resolves deterministically to the code the user was sent last.
        /** @var Otp|null $otp */
        $otp = $this->otps()
            ->where('purpose', $purpose->value())
            ->latest('id')
            ->first();

        $reason = $this->failureReasonFor($otp, $code, $context);

        if (! $reason instanceof FailureReason && $consume) {
            /** @var Otp $otp known non-null: failureReasonFor returned null */
            $reason = $this->consumeRow($otp, $purpose);
        }

        if ($reason instanceof FailureReason) {
            // Deliberately outside any package transaction: the package must
            // never be the reason a failed guess goes unrecorded. (A consumer
            // transaction wrapping this call can still roll the bookkeeping
            // back — PHP cannot escape an outer transaction on the same
            // connection; see the README's consumer transaction caveat.)
            $this->recordAttemptOnFailure($otp);
            $limiter->recordFailure($this, $purpose);
            event(new OtpVerificationFailed($this, $purpose, $reason));

            return false;
        }

        $limiter->clear($this, $purpose);
        event(new OtpVerified($this, $purpose));

        return true;
    }

    /**
     * Single use via compare-and-delete: the delete only wins if the row is
     * still exactly as read (same key, same attempts). A concurrent consume
     * or failed guess landing in the bcrypt window changes that predicate,
     * the delete affects zero rows, and this request reports failure — the
     * same code can never produce two successes.
     */
    private function consumeRow(Otp $otp, OtpPurpose $purpose): ?FailureReason
    {
        $deleted = Otp::query()
            ->whereKey($otp->getKey())
            ->where('attempts', $otp->attempts)
            ->delete();

        if ($deleted !== 1) {
            return FailureReason::NotFound;
        }

        // A concurrently-issued sibling code must not survive a winning
        // consume — sweep every remaining row for this model + purpose.
        $this->otps()->where('purpose', $purpose->value())->delete();

        return null;
    }

    /**
     * Memoized dummy hash for the NotFound timing equalizer. Generated by the
     * runtime hasher (not a hardcoded literal) so its cost always matches the
     * configured bcrypt rounds — a literal baked at one cost would mismatch
     * environments configured with another and re-open a smaller timing gap.
     */
    private static ?string $timingDummyHash = null;

    private function failureReasonFor(?Otp $otp, #[SensitiveParameter] string $code, ?string $context): ?FailureReason
    {
        if (! $otp instanceof Otp) {
            // Burn the same bcrypt work the CodeMismatch path does, so
            // response time cannot reveal whether an active code exists
            // (e.g. "this account has a password reset pending").
            Hash::check($code, self::$timingDummyHash ??= Hash::make('thecyrilcril/laravel-otp:timing-equalizer'));

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

    /**
     * Charge the per-row attempts budget with a direct atomic UPDATE (never
     * a read-modify-write), then retire the row once the budget is spent.
     * Both statements are self-contained, so no transaction is needed and a
     * failed guess is durable even though no lock is held.
     */
    private function recordAttemptOnFailure(?Otp $otp): void
    {
        if (! $otp instanceof Otp) {
            return;
        }

        Otp::query()->whereKey($otp->getKey())->increment('attempts');

        Otp::query()
            ->whereKey($otp->getKey())
            ->where('attempts', '>=', config()->integer('otp.max_attempts', 5))
            ->delete();
    }
}
