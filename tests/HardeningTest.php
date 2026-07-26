<?php

declare(strict_types=1);

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'harden@example.com']);
});

it('never exposes the plaintext code in events or exceptions', function (): void {
    $captured = [];
    Event::listen(OtpIssued::class, function (OtpIssued $e) use (&$captured): void {
        $captured[] = print_r($e, true);
    });
    Event::listen(OtpVerificationFailed::class, function (OtpVerificationFailed $e) use (&$captured): void {
        $captured[] = print_r($e, true);
    });

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);
    $wrong = $issued->code === '999999' ? '111111' : '999999';
    $this->user->verifyOtp(TestPurpose::EmailVerification, $wrong);

    try {
        foreach (range(1, 10) as $i) {
            $this->user->verifyOtp(TestPurpose::EmailVerification, $wrong);
        }
    } catch (OtpThrottledException $e) {
        $captured[] = $e->getMessage();
    }

    foreach ($captured as $payload) {
        expect($payload)->not->toContain($issued->code);
    }
});

it('a code cannot cross purposes even with identical digits', function (): void {
    // Force determinism: issue for one purpose, attempt on another.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::PasswordReset, $issued->code))->toBeFalse()
        ->and($this->user->otps()->where('purpose', 'email_verification')->count())->toBe(1);
});

it('expiry boundary: valid at expiry-1s, dead at expiry+1s', function (): void {
    $this->freezeTime();
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->travel(10 * 60 - 1)->seconds();
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();

    $this->travel(2)->seconds();
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('issuing after a throttled verify still yields a working new code', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 5) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    }

    // Verify limiter is saturated; issuing is governed independently.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect(fn () => $this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))
        ->toThrow(OtpThrottledException::class);
});

it('sequential double-consume: exactly one wins', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $first = $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);
    $second = $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);

    expect($first)->toBeTrue()->and($second)->toBeFalse();
});

it('context comparison tolerates null-issued codes checked with a context', function (): void {
    // Issued without context: presenting one anyway must not error or bind.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code, context: 'anything'))->toBeTrue();
});

it('spends one bcrypt check on every failure path, so timing cannot distinguish them', function (): void {
    // Structural: swap the hash driver for a counting decorator, then assert
    // each failure branch performs exactly one check(). A branch that returns
    // early without hashing is a timing oracle — the Expired branch was one
    // until v0.1.2.
    $counter = new class(app('hash')->driver()) implements Hasher
    {
        public int $checks = 0;

        public function __construct(private readonly Hasher $inner) {}

        /** @param array<string, mixed> $options */
        public function info($hashedValue): array
        {
            return $this->inner->info($hashedValue);
        }

        /** @param array<string, mixed> $options */
        public function make($value, array $options = []): string
        {
            return $this->inner->make($value, $options);
        }

        /** @param array<string, mixed> $options */
        public function check($value, $hashedValue, array $options = []): bool
        {
            $this->checks++;

            return $this->inner->check($value, $hashedValue, $options);
        }

        /** @param array<string, mixed> $options */
        public function needsRehash($hashedValue, array $options = []): bool
        {
            return $this->inner->needsRehash($hashedValue, $options);
        }

        // Not on the Hasher contract, but the `hashed` cast calls it.
        public function isHashed(string $value): bool
        {
            return password_get_info($value)['algo'] !== null;
        }
    };

    app()->instance('hash', $counter);

    // NotFound: no row for this purpose at all.
    $before = $counter->checks;
    $this->user->verifyOtp(TestPurpose::PasswordReset, '000000');
    $notFoundChecks = $counter->checks - $before;

    // Expired: a live row, past its expiry — must still pay the same cost.
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->travel(11)->minutes();
    $before = $counter->checks;
    $this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code);
    $expiredChecks = $counter->checks - $before;
    $this->travelBack();

    expect($notFoundChecks)->toBe(1)
        ->and($expiredChecks)->toBe(1);
});
