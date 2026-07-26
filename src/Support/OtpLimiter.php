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
     * The limiter now counts *attempts*, not just failures: a successful
     * verify consumes one unit of budget here, which {@see self::clear()}
     * immediately refunds on success, so legitimate users are unaffected.
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

    public function clear(Model $otpable, OtpPurpose $purpose): void
    {
        $this->limiter->clear($this->key('verify', $otpable, $purpose));
    }

    private function key(string $side, Model $otpable, OtpPurpose $purpose): string
    {
        return sprintf('otp:%s:%s:%s:%s', $side, $otpable->getMorphClass(), $otpable->getKey(), $purpose->value());
    }
}
