<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Database\Eloquent\Model;
use Thecyrilcril\Otp\Contracts\OtpPurpose;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;

/**
 * Rate limiting for both ends of the OTP lifecycle. Issue limiting throttles
 * mail/SMS bombing (and DoS-by-regeneration against a victim); verify limiting
 * throttles brute force. Keys are scoped per model instance + purpose.
 */
final readonly class OtpLimiter
{
    public function __construct(
        private RateLimiter $limiter,
        private Config $config,
    ) {}

    /**
     * Atomically increments before comparing: `RateLimiter::increment()`
     * returns the post-increment hit count, so the check and the hit are the
     * same cache write. Closes the check-then-hit TOCTOU where N concurrent
     * callers could all read the pre-increment count and all pass.
     */
    public function guardIssue(Model $otpable, OtpPurpose $purpose): void
    {
        $key = $this->key('issue', $otpable, $purpose);
        $max = (int) $this->config->get('otp.issue_limit.attempts', 3);
        $decay = (int) $this->config->get('otp.issue_limit.decay', 600);

        if ($this->limiter->increment($key, $decay) > $max) {
            throw OtpThrottledException::retryIn($this->limiter->availableIn($key));
        }
    }

    /**
     * Atomically increments before comparing (see {@see self::guardIssue()}).
     * The limiter counts *attempts*, not just failures: a successful verify
     * consumes one unit of budget here, which {@see self::refund()} gives
     * back, so legitimate users are unaffected.
     *
     * Note a throttled call also charges the counter, so `RateLimiter::attempts()`
     * reads higher than it did under the old check-then-hit gate. Harmless: the
     * `:timer` key is created with `add`, so extra increments never extend the
     * window — a throttled attacker cannot deepen their own lockout, nor a
     * victim's.
     */
    public function guardVerify(Model $otpable, OtpPurpose $purpose): void
    {
        $key = $this->key('verify', $otpable, $purpose);
        $max = (int) $this->config->get('otp.verify_limit.attempts', 5);
        $decay = (int) $this->config->get('otp.verify_limit.decay', 60);

        if ($this->limiter->increment($key, $decay) > $max) {
            throw OtpThrottledException::retryIn($this->limiter->availableIn($key));
        }
    }

    /**
     * Give back the single unit a successful verify consumed — deliberately
     * NOT a reset of the counter.
     *
     * Since guardVerify became the primary gate, a reset would be an attacker
     * primitive: anyone able to produce one success could zero a nearly
     * exhausted budget and keep guessing indefinitely inside the window. A
     * one-unit refund keeps a legitimate success net-zero while leaving every
     * prior failure banked.
     */
    public function refund(Model $otpable, OtpPurpose $purpose): void
    {
        $decay = (int) $this->config->get('otp.verify_limit.decay', 60);

        $this->limiter->decrement($this->key('verify', $otpable, $purpose), $decay);
    }

    /**
     * Drop the verify budget entirely, as if the window had elapsed.
     *
     * Not used on any verification path — a full reset there would be an
     * attacker primitive (see {@see self::refund()}). This exists for
     * consumers that legitimately need to forgive a lockout out-of-band, e.g.
     * an admin unblocking a user, and for tests that simulate window rollover.
     */
    public function reset(Model $otpable, OtpPurpose $purpose): void
    {
        $this->limiter->clear($this->key('verify', $otpable, $purpose));
    }

    private function key(string $side, Model $otpable, OtpPurpose $purpose): string
    {
        return sprintf('otp:%s:%s:%s:%s', $side, $otpable->getMorphClass(), $otpable->getKey(), $purpose->value());
    }
}
