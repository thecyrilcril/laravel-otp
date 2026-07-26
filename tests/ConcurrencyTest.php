<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Events\OtpVerified;
use Thecyrilcril\Otp\FailureReason;
use Thecyrilcril\Otp\Models\Otp;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'concurrency@example.com']);
});

it('consumes exactly once across two instances of the same user', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    /** @var UuidUser $rival */
    $rival = UuidUser::query()->findOrFail($this->user->getKey());

    Event::fake([OtpVerified::class]);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue()
        ->and($rival->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();

    Event::assertDispatchedTimes(OtpVerified::class, 1);
});

it('leaves no rows for the purpose after a winning consume, even when two codes were live', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    // Simulate the F6 race: a concurrently-issued second (newer) code row
    // exists alongside the first because two issues interleaved.
    $this->user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value(),
        'code' => '999999',
        'expires_at' => CarbonImmutable::now()->addMinutes(10),
    ]);

    expect($this->user->otps()->count())->toBe(2)
        ->and($this->user->consumeOtp(TestPurpose::EmailVerification, '999999'))->toBeTrue()
        ->and($this->user->otps()->count())->toBe(0);
});

it('checks against the newest row when two exist', function (): void {
    $older = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value(),
        'code' => '999999',
        'expires_at' => CarbonImmutable::now()->addMinutes(10),
    ]);

    // The newest code is the live one — it matches what the user was mailed
    // last. The older code no longer verifies.
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, '999999'))->toBeTrue()
        ->and($this->user->verifyOtp(TestPurpose::EmailVerification, $older->code))->toBeFalse();
});

it('charges exactly one attempt per wrong guess', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');

    expect((int) $this->user->otps()->value('attempts'))->toBe(1);
});

// NOTE: this is a PREDICATE test, not a concurrency test. The Hash mock
// replaces real bcrypt and the "race" is a synchronous callback, so it proves
// consumeRow() honours its `attempts` guard — it does not prove race safety
// under real concurrent load. Read it as such.
it('does not report success when the row changed between read and delete', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    /** @var int $otpId */
    $otpId = $this->user->otps()->value('id');

    // Deterministic race: while this request burns bcrypt (after its
    // unlocked read), a concurrent wrong guess lands and bumps the row's
    // attempts. The compare-and-delete predicate no longer matches, so this
    // request must NOT report success even though the code was correct.
    Hash::shouldReceive('check')
        ->once()
        ->andReturnUsing(function () use ($otpId): bool {
            Otp::query()->whereKey($otpId)->increment('attempts');

            return true; // the presented code was correct
        });

    Event::fake([OtpVerified::class, OtpVerificationFailed::class]);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse()
        ->and($this->user->otps()->count())->toBe(1);

    Event::assertNotDispatched(OtpVerified::class);

    // The documented consumeRow() contract for a lost race.
    Event::assertDispatched(
        OtpVerificationFailed::class,
        fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::NotFound,
    );
});

it('does not sweep a code issued after the consumed one', function (): void {
    $user = UuidUser::create(['email' => 'sweep-bound@example.com']);

    // Row A is what the caller will consume. Row B simulates a resend that
    // lands AFTER A was read but before the sweep runs — a higher id.
    $rowA = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '111111',
        'expires_at' => now()->addMinutes(10),
    ]);
    $rowB = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '222222',
        'expires_at' => now()->addMinutes(10),
    ]);
    expect($rowB->getKey())->toBeGreaterThan($rowA->getKey());

    // Drive the consume against row A specifically. consumeOtp() reads
    // latest(id) — so delete B, read A as latest, then restore B to stand in
    // for the resend that raced the sweep.
    $rowB->delete();

    $reflection = new ReflectionMethod($user, 'consumeRow');

    // Re-insert B (higher id than A) immediately before the sweep executes.
    $rowBClone = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '333333',
        'expires_at' => now()->addMinutes(10),
    ]);

    $result = $reflection->invoke($user, $rowA->fresh(), TestPurpose::EmailVerification);

    expect($result)->toBeNull()
        ->and($user->otps()->whereKey($rowA->getKey())->exists())->toBeFalse()
        // The post-dating row must survive the sweep.
        ->and($user->otps()->whereKey($rowBClone->getKey())->exists())->toBeTrue();
});
