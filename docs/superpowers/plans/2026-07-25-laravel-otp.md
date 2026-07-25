# laravel-otp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish `thecyrilcril/laravel-otp` — a purpose-scoped, hashed, rate-limited OTP package per the approved spec at `docs/superpowers/specs/2026-07-25-laravel-otp-design.md`.

**Architecture:** One consumer-facing trait (`HasOtps`) on a polymorphic `Otp` model, backed by focused internal services (`CodeGenerator`, `OtpLimiter`). Codes are bcrypt-hashed at rest via the `hashed` cast; the plaintext exists only in the `IssuedOtp` return value. Consumers supply purposes as backed enums implementing the `OtpPurpose` contract and own all delivery.

**Tech Stack:** PHP ^8.4, illuminate ^12|^13, Pest 4 + orchestra/testbench, Pint, PHPStan (larastan) level 7. Repo/tooling mirrors `thecyrilcril/laravel-impersonate`.

## Global Constraints

- Namespace `Thecyrilcril\Otp`; tests `Thecyrilcril\Otp\Tests`. Package name `thecyrilcril/laravel-otp`.
- Every PHP file: `declare(strict_types=1)` after `<?php` + blank line. Concrete classes `final`. (Pint enforces: preset laravel + `declare_strict_types` + `final_class`.)
- Code length floor of **6** is enforced at runtime — a smaller configured length throws `InvalidArgumentException`.
- The plaintext code must never appear in: DB rows, event payloads, exception messages, `var_dump` of `IssuedOtp`. All `$code` parameters carry `#[\SensitiveParameter]`.
- Every failure path of `verifyOtp`/`consumeOtp` returns bare `false` to the caller (no distinguishable failures externally). Precise reasons go only into `OtpVerificationFailed` events.
- Throttled issue **and** throttled verify/consume throw `OtpThrottledException` (carrying retry-after seconds); throttled verify/consume additionally fires `OtpVerificationFailed` with reason `Throttled`.
- `verifyOtp` is *non-destructive on success* — but failed checks still hit the rate limiter and the per-row `attempts` counter (spec self-review note).
- Config keys exactly: `length`, `expires_after`, `verify_limit.attempts`, `verify_limit.decay`, `issue_limit.attempts`, `issue_limit.decay`, `max_attempts`, `table`. Defaults: 6, 10, 5/60, 3/600, 5, `otps`.
- Run the full gate with `composer ci` (Pint test-mode, PHPStan, Pest with coverage) before declaring any task done.
- Working directory for every command: `/Users/user/Code/laravel-otp`.

---

### Task 1: Package scaffolding + boot smoke test

**Files:**
- Create: `composer.json`, `pint.json`, `phpstan.neon`, `phpunit.xml`, `.gitignore`
- Create: `config/otp.php`
- Create: `src/OtpServiceProvider.php`
- Create: `tests/Pest.php`, `tests/TestCase.php`
- Test: `tests/ServiceProviderTest.php`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `Thecyrilcril\Otp\OtpServiceProvider` (registers `otp` config, publishes config + migrations); `Tests\TestCase` extending Orchestra with an in-memory sqlite DB and two user tables (`users` uuid-keyed, `int_users` bigint-keyed) that all later tasks' fixtures use.

- [ ] **Step 1: Write composer.json, tool configs, config file, provider, test bootstrap**

`composer.json`:

```json
{
    "name": "thecyrilcril/laravel-otp",
    "description": "Purpose-scoped, hashed, rate-limited one-time passwords for Laravel.",
    "keywords": ["laravel", "otp", "one-time-password", "verification", "security"],
    "license": "MIT",
    "authors": [
        { "name": "Cyril Cril", "email": "cyrilcril@gmail.com" }
    ],
    "require": {
        "php": "^8.4",
        "illuminate/contracts": "^12.0|^13.0",
        "illuminate/database": "^12.0|^13.0",
        "illuminate/support": "^12.0|^13.0"
    },
    "require-dev": {
        "orchestra/testbench": "^10.0|^11.0",
        "pestphp/pest": "^4.0",
        "laravel/pint": "^1.24",
        "phpstan/phpstan": "^2.1",
        "larastan/larastan": "^3.0"
    },
    "autoload": {
        "psr-4": { "Thecyrilcril\\Otp\\": "src/" }
    },
    "autoload-dev": {
        "psr-4": { "Thecyrilcril\\Otp\\Tests\\": "tests/" }
    },
    "config": {
        "sort-packages": true,
        "allow-plugins": { "pestphp/pest-plugin": true }
    },
    "extra": {
        "laravel": {
            "providers": ["Thecyrilcril\\Otp\\OtpServiceProvider"]
        }
    },
    "scripts": {
        "test": "vendor/bin/pest",
        "test:coverage": "@php -d xdebug.mode=coverage vendor/bin/pest --coverage --min=90",
        "lint": "vendor/bin/pint",
        "analyse": "vendor/bin/phpstan analyse",
        "ci": [
            "@lint --test",
            "@analyse",
            "@test:coverage"
        ]
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

`pint.json`:

```json
{
    "preset": "laravel",
    "rules": {
        "declare_strict_types": true,
        "final_class": true,
        "ordered_imports": { "sort_algorithm": "alpha" },
        "no_unused_imports": true
    }
}
```

`phpstan.neon`:

```neon
includes:
    - vendor/larastan/larastan/extension.neon

parameters:
    level: 7
    paths:
        - src
    tmpDir: build/phpstan
    ignoreErrors:
        # HasOtps is a public trait for consumers' models; it has no in-package
        # consumer, so larastan cannot see it as used.
        -
            identifier: trait.unused
            path: src/Concerns/HasOtps.php
```

`phpunit.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true"
         cacheDirectory=".phpunit.cache">
    <testsuites>
        <testsuite name="Test Suite">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
    <source>
        <include>
            <directory>src</directory>
        </include>
    </source>
</phpunit>
```

`.gitignore`:

```
/vendor/
/build/
/.phpunit.cache/
composer.lock
.DS_Store
```

`config/otp.php`:

```php
<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Code Length
    |--------------------------------------------------------------------------
    |
    | Number of digits in a generated code. The package enforces a floor of
    | six at runtime: a smaller value throws, because a shorter numeric code
    | is brute-forceable even through the rate limiter.
    |
    */

    'length' => 6,

    /*
    |--------------------------------------------------------------------------
    | Expiry (minutes)
    |--------------------------------------------------------------------------
    */

    'expires_after' => 10,

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | verify_limit: failed verification attempts allowed per model+purpose
    | within the decay window (seconds).
    | issue_limit: codes that may be issued per model+purpose within the
    | decay window (seconds) — throttles mail/SMS bombing.
    | max_attempts: per-code failure budget; exceeded => the code is deleted
    | even if the limiter window has rolled over.
    |
    */

    'verify_limit' => ['attempts' => 5, 'decay' => 60],
    'issue_limit' => ['attempts' => 3, 'decay' => 600],
    'max_attempts' => 5,

    /*
    |--------------------------------------------------------------------------
    | Table
    |--------------------------------------------------------------------------
    */

    'table' => 'otps',

];
```

`src/OtpServiceProvider.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

use Illuminate\Support\ServiceProvider;

final class OtpServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'otp');
    }

    public function boot(): void
    {
        $this->publishes([
            $this->configPath() => $this->app->configPath('otp.php'),
        ], 'otp-config');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => $this->app->databasePath('migrations'),
        ], 'otp-migrations');
    }

    private function configPath(): string
    {
        return __DIR__.'/../config/otp.php';
    }
}
```

`tests/Pest.php`:

```php
<?php

declare(strict_types=1);

use Thecyrilcril\Otp\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);
```

`tests/TestCase.php` — two parent tables so morph support is proven against uuid AND bigint keys:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Thecyrilcril\Otp\OtpServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('users', static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->unique();
            $table->timestamps();
        });

        Schema::create('int_users', static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email')->unique();
            $table->timestamps();
        });

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            OtpServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app['config'];

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $config->set('cache.default', 'array');
    }
}
```

`tests/ServiceProviderTest.php`:

```php
<?php

declare(strict_types=1);

it('boots and merges the otp config', function (): void {
    expect(config('otp.length'))->toBe(6)
        ->and(config('otp.expires_after'))->toBe(10)
        ->and(config('otp.verify_limit'))->toBe(['attempts' => 5, 'decay' => 60])
        ->and(config('otp.issue_limit'))->toBe(['attempts' => 3, 'decay' => 600])
        ->and(config('otp.max_attempts'))->toBe(5)
        ->and(config('otp.table'))->toBe('otps');
});
```

- [ ] **Step 2: Install dependencies and run the test to verify it fails correctly**

Run: `cd /Users/user/Code/laravel-otp && composer install`
Then: `vendor/bin/pest tests/ServiceProviderTest.php`
Expected: **ERROR** — `loadMigrationsFrom` points at a directory that doesn't exist yet (created in Task 2). If testbench tolerates the empty path, the test PASSES — either outcome is acceptable; the migration lands next task. If it errors, temporarily create the empty dir: `mkdir -p database/migrations`, re-run, expect PASS.

- [ ] **Step 3: Run the linters to lock in tooling**

Run: `vendor/bin/pint --test && vendor/bin/phpstan analyse`
Expected: both pass (fix anything Pint flags with `vendor/bin/pint`).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: scaffold package with provider, config and test harness"
```

---

### Task 2: `OtpPurpose` contract, `Otp` model, migration

**Files:**
- Create: `src/Contracts/OtpPurpose.php`
- Create: `src/Models/Otp.php`
- Create: `database/migrations/2026_07_25_000000_create_otps_table.php`
- Create: `tests/Fixtures/TestPurpose.php`, `tests/Fixtures/UuidUser.php`, `tests/Fixtures/IntUser.php`
- Test: `tests/OtpModelTest.php`

**Interfaces:**
- Consumes: `TestCase` schema from Task 1.
- Produces: `OtpPurpose` contract (`public function value(): string`); `Models\Otp` with `otpable()` morph, casts (`code => hashed`, `expires_at => immutable_datetime`, `attempts => integer`), `isExpired(): bool`, `prunable()`; fixtures `TestPurpose` (cases `EmailVerification = 'email_verification'`, `PasswordReset = 'password_reset'`, `PhoneVerification = 'phone_verification'`), `UuidUser`, `IntUser` — later tasks build on all of these.

- [ ] **Step 1: Write the failing tests**

`tests/OtpModelTest.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Thecyrilcril\Otp\Models\Otp;
use Thecyrilcril\Otp\Tests\Fixtures\IntUser;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

it('stores the code hashed, never plaintext', function (): void {
    $user = UuidUser::create(['email' => 'a@example.com']);

    $otp = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '123456',
        'expires_at' => now()->addMinutes(10),
    ]);

    $raw = $otp->getRawOriginal('code');

    expect($raw)->not->toBe('123456')
        ->and(Hash::check('123456', $raw))->toBeTrue();
});

it('morphs to uuid-keyed and bigint-keyed parents', function (): void {
    $uuidUser = UuidUser::create(['email' => 'u@example.com']);
    $intUser = IntUser::create(['email' => 'i@example.com']);

    $a = $uuidUser->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '111111',
        'expires_at' => now()->addMinutes(10),
    ]);
    $b = $intUser->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '222222',
        'expires_at' => now()->addMinutes(10),
    ]);

    expect($a->otpable)->toBeInstanceOf(UuidUser::class)
        ->and($a->otpable->getKey())->toBe($uuidUser->getKey())
        ->and($b->otpable)->toBeInstanceOf(IntUser::class)
        ->and($b->otpable->getKey())->toBe($intUser->getKey());
});

it('knows whether it is expired', function (): void {
    $user = UuidUser::create(['email' => 'e@example.com']);

    $live = $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '123456',
        'expires_at' => now()->addMinute(),
    ]);
    $dead = $user->otps()->create([
        'purpose' => TestPurpose::PasswordReset->value,
        'code' => '123456',
        'expires_at' => now()->subSecond(),
    ]);

    expect($live->isExpired())->toBeFalse()
        ->and($dead->isExpired())->toBeTrue();
});

it('prunes only expired rows', function (): void {
    $user = UuidUser::create(['email' => 'p@example.com']);

    $user->otps()->create([
        'purpose' => TestPurpose::EmailVerification->value,
        'code' => '111111',
        'expires_at' => now()->subMinute(),
    ]);
    $user->otps()->create([
        'purpose' => TestPurpose::PasswordReset->value,
        'code' => '222222',
        'expires_at' => now()->addMinutes(10),
    ]);

    $pruned = (new Otp())->prunable()->count();

    expect($pruned)->toBe(1);
});

it('accepts any backed string enum through the contract', function (): void {
    expect(TestPurpose::EmailVerification->value())->toBe('email_verification')
        ->and(TestPurpose::PhoneVerification->value())->toBe('phone_verification');
});
```

`tests/Fixtures/TestPurpose.php`:

```php
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
```

> PHP note: a backed enum's `$this->value` property and a `value()` method coexist without
> conflict — the contract method simply returns the case's backing value.

`tests/Fixtures/UuidUser.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Tests\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Thecyrilcril\Otp\Concerns\HasOtps;

final class UuidUser extends Model
{
    use HasOtps;
    use HasUuids;

    protected $table = 'users';

    protected $guarded = [];
}
```

`tests/Fixtures/IntUser.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Tests\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Thecyrilcril\Otp\Concerns\HasOtps;

final class IntUser extends Model
{
    use HasOtps;

    protected $table = 'int_users';

    protected $guarded = [];
}
```

> The fixtures reference `HasOtps`, which does not exist until Task 4. To keep this task
> self-contained and RED-GREEN honest, create the **minimal** trait now (relation only —
> Task 4 grows it):

`src/Concerns/HasOtps.php` (minimal seed version):

```php
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/OtpModelTest.php`
Expected: FAIL — `Class "Thecyrilcril\Otp\Models\Otp" not found` / missing contract / missing table.

- [ ] **Step 3: Write the implementation**

`src/Contracts/OtpPurpose.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Contracts;

/**
 * Implemented by consumer-supplied backed string enums. The returned value is
 * stored in the `purpose` column and scopes every OTP operation: a code issued
 * for one purpose can never satisfy a check for another.
 */
interface OtpPurpose
{
    public function value(): string;
}
```

`database/migrations/2026_07_25_000000_create_otps_table.php` (forward-only — no `down()`, matching the owner's convention):

```php
<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config()->string('otp.table', 'otps'), static function (Blueprint $table): void {
            $table->id();
            $table->string('otpable_type');
            $table->string('otpable_id');
            $table->string('purpose', 64);
            $table->string('code');
            $table->string('context')->nullable();
            $table->unsignedSmallInteger('attempts')->default(0);
            $table->timestamp('expires_at');
            $table->timestamps();

            $table->index(['otpable_type', 'otpable_id', 'purpose'], 'otps_otpable_purpose_index');
            $table->index('expires_at');
        });
    }
};
```

`src/Models/Otp.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property string $otpable_type
 * @property string $otpable_id
 * @property string $purpose
 * @property string $code bcrypt hash at rest (hashed cast)
 * @property string|null $context The target the code was sent to (address, not secret)
 * @property int $attempts
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 * @property-read Model $otpable
 */
final class Otp extends Model
{
    use MassPrunable;

    protected $guarded = [];

    public function getTable(): string
    {
        return config()->string('otp.table', 'otps');
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function otpable(): MorphTo
    {
        return $this->morphTo();
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('expires_at', '<', now());
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'code' => 'hashed',
            'context' => 'string',
            'attempts' => 'integer',
            'expires_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `vendor/bin/pest tests/OtpModelTest.php tests/ServiceProviderTest.php`
Expected: PASS (all).

- [ ] **Step 5: Lint, analyse, commit**

```bash
vendor/bin/pint && vendor/bin/phpstan analyse
git add -A
git commit -m "feat: add OtpPurpose contract, Otp model and migration"
```

---

### Task 3: `CodeGenerator`, `IssuedOtp`, `OtpThrottledException`, events

**Files:**
- Create: `src/Support/CodeGenerator.php`
- Create: `src/IssuedOtp.php`
- Create: `src/Exceptions/OtpThrottledException.php`
- Create: `src/Events/OtpIssued.php`, `src/Events/OtpVerified.php`, `src/Events/OtpVerificationFailed.php`, `src/FailureReason.php`
- Test: `tests/CodeGeneratorTest.php`, `tests/IssuedOtpTest.php`

**Interfaces:**
- Consumes: `OtpPurpose` contract (Task 2).
- Produces:
  - `CodeGenerator::generate(int $length): string` — throws `InvalidArgumentException` when `$length < 6`.
  - `IssuedOtp` readonly: `->code` (string plaintext), `->expiresAt` (`CarbonImmutable`); `__debugInfo()` masks the code.
  - `OtpThrottledException` with `public readonly int $retryAfterSeconds` and static constructor `::retryIn(int $seconds)`.
  - `FailureReason` enum: `NotFound`, `Expired`, `CodeMismatch`, `ContextMismatch`, `Throttled`.
  - Events: `OtpIssued(Model $otpable, OtpPurpose $purpose)`, `OtpVerified(Model $otpable, OtpPurpose $purpose)`, `OtpVerificationFailed(Model $otpable, OtpPurpose $purpose, FailureReason $reason)`.

- [ ] **Step 1: Write the failing tests**

`tests/CodeGeneratorTest.php`:

```php
<?php

declare(strict_types=1);

use Thecyrilcril\Otp\Support\CodeGenerator;

it('generates codes of the requested length, digits only, zero-padded', function (): void {
    $generator = new CodeGenerator();

    foreach (range(1, 50) as $i) {
        $code = $generator->generate(6);
        expect($code)->toMatchExpression(fn (string $c): bool => strlen($c) === 6 && ctype_digit($c));
    }

    $long = $generator->generate(8);
    expect(strlen($long))->toBe(8)
        ->and(ctype_digit($long))->toBeTrue();
});

it('refuses lengths below six', function (): void {
    (new CodeGenerator())->generate(4);
})->throws(InvalidArgumentException::class, 'at least 6');
```

> If `toMatchExpression` is unavailable in the installed Pest version, replace that line with
> `expect(strlen($code))->toBe(6); expect(ctype_digit($code))->toBeTrue();`

`tests/IssuedOtpTest.php`:

```php
<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Thecyrilcril\Otp\IssuedOtp;

it('exposes the code and expiry', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    expect($issued->code)->toBe('123456')
        ->and($issued->expiresAt)->toBeInstanceOf(CarbonImmutable::class);
});

it('masks the code in debug output', function (): void {
    $issued = new IssuedOtp('123456', CarbonImmutable::now()->addMinutes(10));

    $dump = print_r($issued->__debugInfo(), true);

    expect($dump)->not->toContain('123456')
        ->and($dump)->toContain('******');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/CodeGeneratorTest.php tests/IssuedOtpTest.php`
Expected: FAIL — classes not found.

- [ ] **Step 3: Write the implementations**

`src/Support/CodeGenerator.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Support;

use InvalidArgumentException;

final class CodeGenerator
{
    private const int MINIMUM_LENGTH = 6;

    /**
     * Generate a cryptographically random, zero-padded numeric code.
     */
    public function generate(int $length): string
    {
        if ($length < self::MINIMUM_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('OTP length must be at least %d digits, %d configured.', self::MINIMUM_LENGTH, $length)
            );
        }

        $max = (10 ** $length) - 1;

        return str_pad((string) random_int(0, $max), $length, '0', STR_PAD_LEFT);
    }
}
```

`src/IssuedOtp.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * The one-time exposure of a plaintext OTP code. Returned by issueOtp() so the
 * consumer can hand the code to its own notification; never persisted, never
 * logged (debug output masks it).
 */
final readonly class IssuedOtp
{
    public function __construct(
        #[SensitiveParameter] public string $code,
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'code' => '******',
            'expiresAt' => $this->expiresAt->toIso8601String(),
        ];
    }
}
```

`src/Exceptions/OtpThrottledException.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Exceptions;

use RuntimeException;

final class OtpThrottledException extends RuntimeException
{
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct(sprintf('Too many OTP attempts. Retry in %d seconds.', $retryAfterSeconds));
    }

    public static function retryIn(int $seconds): self
    {
        return new self($seconds);
    }
}
```

`src/FailureReason.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp;

enum FailureReason: string
{
    case NotFound = 'not_found';
    case Expired = 'expired';
    case CodeMismatch = 'code_mismatch';
    case ContextMismatch = 'context_mismatch';
    case Throttled = 'throttled';
}
```

`src/Events/OtpIssued.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Thecyrilcril\Otp\Contracts\OtpPurpose;

final class OtpIssued
{
    use Dispatchable;

    public function __construct(
        public readonly Model $otpable,
        public readonly OtpPurpose $purpose,
    ) {}
}
```

`src/Events/OtpVerified.php`:

```php
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
```

`src/Events/OtpVerificationFailed.php`:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Thecyrilcril\Otp\Contracts\OtpPurpose;
use Thecyrilcril\Otp\FailureReason;

final class OtpVerificationFailed
{
    use Dispatchable;

    public function __construct(
        public readonly Model $otpable,
        public readonly OtpPurpose $purpose,
        public readonly FailureReason $reason,
    ) {}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `vendor/bin/pest tests/CodeGeneratorTest.php tests/IssuedOtpTest.php`
Expected: PASS.

- [ ] **Step 5: Lint, analyse, commit**

```bash
vendor/bin/pint && vendor/bin/phpstan analyse
git add -A
git commit -m "feat: add code generator, issued-otp value object, events and throttle exception"
```

---

### Task 4: `OtpLimiter` (both-ends rate limiting)

**Files:**
- Create: `src/Support/OtpLimiter.php`
- Test: `tests/OtpLimiterTest.php`

**Interfaces:**
- Consumes: `OtpThrottledException` (Task 3), config keys (Task 1).
- Produces (all keyed per model+purpose):
  - `guardIssue(Model $otpable, OtpPurpose $purpose): void` — throws `OtpThrottledException` past the issue limit; otherwise records the hit.
  - `guardVerify(Model $otpable, OtpPurpose $purpose): void` — throws past the verify limit; does NOT record (failures record explicitly).
  - `recordFailure(Model $otpable, OtpPurpose $purpose): void` — hits the verify limiter.
  - `clear(Model $otpable, OtpPurpose $purpose): void` — clears the verify limiter after success.

- [ ] **Step 1: Write the failing tests**

`tests/OtpLimiterTest.php`:

```php
<?php

declare(strict_types=1);

use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\Support\OtpLimiter;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'limits@example.com']);
    $this->limiter = app(OtpLimiter::class);
});

it('allows issuance up to the limit then throttles with retry-after', function (): void {
    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    try {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
        $this->fail('Expected OtpThrottledException');
    } catch (OtpThrottledException $e) {
        expect($e->retryAfterSeconds)->toBeGreaterThan(0)
            ->and($e->retryAfterSeconds)->toBeLessThanOrEqual(600);
    }
});

it('scopes limits per purpose', function (): void {
    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    // Different purpose: unaffected.
    $this->limiter->guardIssue($this->user, TestPurpose::PasswordReset);
    expect(true)->toBeTrue();
});

it('scopes limits per user', function (): void {
    $other = UuidUser::create(['email' => 'other@example.com']);

    foreach (range(1, 3) as $i) {
        $this->limiter->guardIssue($this->user, TestPurpose::EmailVerification);
    }

    $this->limiter->guardIssue($other, TestPurpose::EmailVerification);
    expect(true)->toBeTrue();
});

it('throttles verification after the configured failures and clears on demand', function (): void {
    foreach (range(1, 5) as $i) {
        $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
        $this->limiter->recordFailure($this->user, TestPurpose::EmailVerification);
    }

    expect(fn () => $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);

    $this->limiter->clear($this->user, TestPurpose::EmailVerification);
    $this->limiter->guardVerify($this->user, TestPurpose::EmailVerification);
    expect(true)->toBeTrue();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/OtpLimiterTest.php`
Expected: FAIL — `OtpLimiter` not found.

- [ ] **Step 3: Write the implementation**

`src/Support/OtpLimiter.php`:

```php
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

    public function guardIssue(Model $otpable, OtpPurpose $purpose): void
    {
        $key = $this->key('issue', $otpable, $purpose);
        $max = (int) $this->config->get('otp.issue_limit.attempts', 3);
        $decay = (int) $this->config->get('otp.issue_limit.decay', 600);

        if ($this->limiter->tooManyAttempts($key, $max)) {
            throw OtpThrottledException::retryIn($this->limiter->availableIn($key));
        }

        $this->limiter->hit($key, $decay);
    }

    public function guardVerify(Model $otpable, OtpPurpose $purpose): void
    {
        $key = $this->key('verify', $otpable, $purpose);
        $max = (int) $this->config->get('otp.verify_limit.attempts', 5);

        if ($this->limiter->tooManyAttempts($key, $max)) {
            throw OtpThrottledException::retryIn($this->limiter->availableIn($key));
        }
    }

    public function recordFailure(Model $otpable, OtpPurpose $purpose): void
    {
        $decay = (int) $this->config->get('otp.verify_limit.decay', 60);

        $this->limiter->hit($this->key('verify', $otpable, $purpose), $decay);
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `vendor/bin/pest tests/OtpLimiterTest.php`
Expected: PASS.

- [ ] **Step 5: Lint, analyse, commit**

```bash
vendor/bin/pint && vendor/bin/phpstan analyse
git add -A
git commit -m "feat: add per-model+purpose rate limiting for issue and verify"
```

---

### Task 5: `HasOtps::issueOtp()`

**Files:**
- Modify: `src/Concerns/HasOtps.php` (grow the Task 2 seed)
- Test: `tests/IssueOtpTest.php`

**Interfaces:**
- Consumes: `Otp` model, `CodeGenerator`, `OtpLimiter`, `IssuedOtp`, `OtpIssued` event, `OtpPurpose`.
- Produces: `issueOtp(OtpPurpose $purpose, ?string $context = null): IssuedOtp` — exact signature Task 6/7 tests reuse.

- [ ] **Step 1: Write the failing tests**

`tests/IssueOtpTest.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Thecyrilcril\Otp\Events\OtpIssued;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\IssuedOtp;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'issue@example.com']);
});

it('issues a hashed code and returns the plaintext once', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($issued)->toBeInstanceOf(IssuedOtp::class)
        ->and(strlen($issued->code))->toBe(6)
        ->and(ctype_digit($issued->code))->toBeTrue();

    $row = $this->user->otps()->sole();

    expect($row->purpose)->toBe('email_verification')
        ->and($row->getRawOriginal('code'))->not->toBe($issued->code)
        ->and(Hash::check($issued->code, $row->getRawOriginal('code')))->toBeTrue()
        ->and($row->context)->toBeNull()
        ->and($row->attempts)->toBe(0);
});

it('sets expiry from config', function (): void {
    $this->freezeTime();

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($issued->expiresAt->timestamp)->toBe(now()->addMinutes(10)->timestamp);
});

it('stores the context when given', function (): void {
    $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->otps()->sole()->context)->toBe('+2348012345678');
});

it('replaces any existing code for the same purpose', function (): void {
    $first = $this->user->issueOtp(TestPurpose::EmailVerification);
    $second = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->otps()->count())->toBe(1)
        ->and(Hash::check($second->code, $this->user->otps()->sole()->getRawOriginal('code')))->toBeTrue()
        ->and(Hash::check($first->code, $this->user->otps()->sole()->getRawOriginal('code')))->toBeFalse();
});

it('keeps codes for different purposes independent', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->user->issueOtp(TestPurpose::PasswordReset);

    expect($this->user->otps()->count())->toBe(2);
});

it('fires OtpIssued without leaking the code', function (): void {
    Event::fake([OtpIssued::class]);

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    Event::assertDispatched(OtpIssued::class, function (OtpIssued $event) use ($issued): bool {
        return $event->otpable->is($this->user)
            && $event->purpose === TestPurpose::EmailVerification
            && ! str_contains(print_r($event, true), $issued->code);
    });
});

it('throttles issuance past the configured limit', function (): void {
    foreach (range(1, 3) as $i) {
        $this->user->issueOtp(TestPurpose::EmailVerification);
    }

    expect(fn () => $this->user->issueOtp(TestPurpose::EmailVerification))
        ->toThrow(OtpThrottledException::class);
});

it('rejects a code length configured below six', function (): void {
    config()->set('otp.length', 4);

    expect(fn () => $this->user->issueOtp(TestPurpose::EmailVerification))
        ->toThrow(InvalidArgumentException::class);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/IssueOtpTest.php`
Expected: FAIL — `issueOtp` undefined.

- [ ] **Step 3: Grow the trait**

Replace `src/Concerns/HasOtps.php` with:

```php
<?php

declare(strict_types=1);

namespace Thecyrilcril\Otp\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Thecyrilcril\Otp\Contracts\OtpPurpose;
use Thecyrilcril\Otp\Events\OtpIssued;
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
     * @throws \Thecyrilcril\Otp\Exceptions\OtpThrottledException
     * @throws \InvalidArgumentException when the configured length is below 6
     */
    public function issueOtp(OtpPurpose $purpose, ?string $context = null): IssuedOtp
    {
        app(OtpLimiter::class)->guardIssue($this, $purpose);

        $code = app(CodeGenerator::class)->generate(config()->integer('otp.length', 6));
        $expiresAt = CarbonImmutable::now()->addMinutes(config()->integer('otp.expires_after', 10));

        $this->otps()->where('purpose', $purpose->value())->delete();

        $this->otps()->create([
            'purpose' => $purpose->value(),
            'code' => $code,
            'context' => $context,
            'expires_at' => $expiresAt,
        ]);

        event(new OtpIssued($this, $purpose));

        return new IssuedOtp($code, $expiresAt);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `vendor/bin/pest tests/IssueOtpTest.php`
Expected: PASS.

- [ ] **Step 5: Lint, analyse, commit**

```bash
vendor/bin/pint && vendor/bin/phpstan analyse
git add -A
git commit -m "feat: add issueOtp with replacement, context, throttle and event"
```

---

### Task 6: `HasOtps::verifyOtp()` and `consumeOtp()`

**Files:**
- Modify: `src/Concerns/HasOtps.php`
- Test: `tests/VerifyOtpTest.php`, `tests/ConsumeOtpTest.php`

**Interfaces:**
- Consumes: everything produced so far.
- Produces:
  - `verifyOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context = null): bool`
  - `consumeOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context = null): bool`
  - Check order (both): limiter → row lookup → expiry → `Hash::check` → context `hash_equals`. Failure → `false` + limiter hit + row `attempts` increment (row deleted at `max_attempts`) + `OtpVerificationFailed`. Success: verify clears limiter and leaves the row; consume clears limiter and deletes the row inside `DB::transaction` + `lockForUpdate`.

- [ ] **Step 1: Write the failing tests**

`tests/VerifyOtpTest.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpVerificationFailed;
use Thecyrilcril\Otp\Exceptions\OtpThrottledException;
use Thecyrilcril\Otp\FailureReason;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'verify@example.com']);
});

it('verifies a correct code without consuming it', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue()
        ->and($this->user->otps()->count())->toBe(1);

    // Repeatable while un-consumed.
    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});

it('returns bare false for every failure mode', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    // Wrong code / wrong purpose / wrong context / no row at all — all identical to the caller.
    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, '000000', context: '+2348012345678'))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000'))->toBeFalse();
});

it('rejects an expired code', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    $this->travel(11)->minutes();

    expect($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('binds a code to its issued context', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    // Phone A → verify with phone B fails; with A succeeds.
    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2349999999999'))->toBeFalse()
        ->and($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2348012345678'))->toBeTrue();
});

it('requires the context when one was issued, even if omitted at verify time', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code))->toBeFalse();
});

it('fires precise failure events while the caller sees only false', function (): void {
    Event::fake([OtpVerificationFailed::class]);

    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    $this->user->verifyOtp(TestPurpose::PhoneVerification, '000000', context: '+2348012345678');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::CodeMismatch);

    $this->user->verifyOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::ContextMismatch);

    $this->user->verifyOtp(TestPurpose::PasswordReset, '000000');
    Event::assertDispatched(OtpVerificationFailed::class, fn (OtpVerificationFailed $e): bool => $e->reason === FailureReason::NotFound);
});

it('kills the code after max_attempts failures, independent of the limiter window', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 4) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
        // Reset the limiter each round to prove the per-row counter acts alone.
        app(Thecyrilcril\Otp\Support\OtpLimiter::class)->clear($this->user, TestPurpose::EmailVerification);
    }

    // 5th failure deletes the row.
    $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    app(Thecyrilcril\Otp\Support\OtpLimiter::class)->clear($this->user, TestPurpose::EmailVerification);

    expect($this->user->otps()->count())->toBe(0)
        ->and($this->user->verifyOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('throttles verification attempts past the limit', function (): void {
    $this->user->issueOtp(TestPurpose::EmailVerification);

    foreach (range(1, 5) as $i) {
        $this->user->verifyOtp(TestPurpose::EmailVerification, '000000');
    }

    expect(fn () => $this->user->verifyOtp(TestPurpose::EmailVerification, '000000'))
        ->toThrow(OtpThrottledException::class);
});
```

`tests/ConsumeOtpTest.php`:

```php
<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Thecyrilcril\Otp\Events\OtpVerified;
use Thecyrilcril\Otp\Tests\Fixtures\TestPurpose;
use Thecyrilcril\Otp\Tests\Fixtures\UuidUser;

beforeEach(function (): void {
    $this->user = UuidUser::create(['email' => 'consume@example.com']);
});

it('consumes a correct code exactly once', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue()
        ->and($this->user->otps()->count())->toBe(0);

    // Replay: the code is gone.
    expect($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeFalse();
});

it('fires OtpVerified on successful consumption', function (): void {
    Event::fake([OtpVerified::class]);

    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);
    $this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code);

    Event::assertDispatched(OtpVerified::class, fn (OtpVerified $e): bool => $e->otpable->is($this->user)
        && $e->purpose === TestPurpose::EmailVerification);
});

it('does not consume on a wrong code', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::EmailVerification);

    expect($this->user->consumeOtp(TestPurpose::EmailVerification, '000000'))->toBeFalse()
        ->and($this->user->otps()->count())->toBe(1)
        ->and($this->user->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});

it('enforces context binding on consumption', function (): void {
    $issued = $this->user->issueOtp(TestPurpose::PhoneVerification, context: '+2348012345678');

    expect($this->user->consumeOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2340000000000'))->toBeFalse()
        ->and($this->user->consumeOtp(TestPurpose::PhoneVerification, $issued->code, context: '+2348012345678'))->toBeTrue();
});

it('works identically on a bigint-keyed parent', function (): void {
    $intUser = Thecyrilcril\Otp\Tests\Fixtures\IntUser::create(['email' => 'int@example.com']);

    $issued = $intUser->issueOtp(TestPurpose::EmailVerification);

    expect($intUser->consumeOtp(TestPurpose::EmailVerification, $issued->code))->toBeTrue();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/VerifyOtpTest.php tests/ConsumeOtpTest.php`
Expected: FAIL — `verifyOtp` / `consumeOtp` undefined.

- [ ] **Step 3: Add verification to the trait**

Append to `src/Concerns/HasOtps.php` (inside the trait; add the new imports to the `use` block: `Illuminate\Support\Facades\DB`, `Illuminate\Support\Facades\Hash`, `SensitiveParameter`, `Thecyrilcril\Otp\Events\OtpVerificationFailed`, `Thecyrilcril\Otp\Events\OtpVerified`, `Thecyrilcril\Otp\FailureReason`):

```php
    /**
     * Check a code without consuming it. Non-destructive on success — but a
     * failed check still counts against the rate limiter and the per-row
     * attempts budget, or this would be a counter-free brute-force channel.
     *
     * @throws \Thecyrilcril\Otp\Exceptions\OtpThrottledException
     */
    public function verifyOtp(OtpPurpose $purpose, #[SensitiveParameter] string $code, ?string $context = null): bool
    {
        return $this->checkOtp($purpose, $code, $context, consume: false);
    }

    /**
     * Check a code and, on success, delete it atomically (single use).
     *
     * @throws \Thecyrilcril\Otp\Exceptions\OtpThrottledException
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
        } catch (\Thecyrilcril\Otp\Exceptions\OtpThrottledException $e) {
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
```

- [ ] **Step 4: Run the full suite to verify everything passes**

Run: `vendor/bin/pest`
Expected: PASS (all files).

- [ ] **Step 5: Lint, analyse, commit**

```bash
vendor/bin/pint && vendor/bin/phpstan analyse
git add -A
git commit -m "feat: add verifyOtp and consumeOtp with ordered checks, counters and events"
```

---

### Task 7: Hardening test suite (attack-shaped, cross-cutting)

**Files:**
- Test: `tests/HardeningTest.php`

**Interfaces:**
- Consumes: the complete public API (Tasks 5–6). No new production code expected — this task exists to *prove* the security posture and to catch anything the unit-level suites missed. If any test here fails, fix the production code in place.

- [ ] **Step 1: Write the tests**

`tests/HardeningTest.php`:

```php
<?php

declare(strict_types=1);

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
    $this->user->verifyOtp(TestPurpose::EmailVerification, '999999');

    try {
        foreach (range(1, 10) as $i) {
            $this->user->verifyOtp(TestPurpose::EmailVerification, '999999');
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
```

> Note on true parallel consumes: `lockForUpdate` is a no-op on in-memory sqlite, so genuine
> concurrency is not provable in this suite. The transaction+lock code path *is* exercised
> (sequential double-consume proves single-use), and the lock is real on MySQL/Postgres in
> consumers. Do not add a flaky threads-based test.

- [ ] **Step 2: Run the suite**

Run: `vendor/bin/pest tests/HardeningTest.php`
Expected: PASS. Any failure here is a production bug — fix `src/`, not the test, and note what was found in the commit message.

- [ ] **Step 3: Full gate**

Run: `composer ci`
Expected: Pint clean, PHPStan clean, Pest green with coverage ≥ 90%.
If coverage is below the bar, the uncovered lines are almost certainly failure branches — cover them with targeted tests rather than lowering the threshold.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test: add attack-shaped hardening suite"
```

---

### Task 8: README, CI workflow, release prep

**Files:**
- Create: `README.md`, `LICENSE.md`, `CHANGELOG.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the finished API (for documentation accuracy).
- Produces: the public face of the package. No production code.

- [ ] **Step 1: Write the CI workflow**

`.github/workflows/ci.yml` (same shape as impersonate):

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  ci:
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        laravel: ['12.*', '13.*']

    name: Laravel ${{ matrix.laravel }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          coverage: xdebug

      - name: Install dependencies
        run: |
          composer require "illuminate/support:${{ matrix.laravel }}" --no-interaction --no-update
          composer update --prefer-dist --no-interaction

      - name: Run CI suite (Pint, PHPStan, Pest with coverage)
        run: composer ci
```

- [ ] **Step 2: Write LICENSE.md (MIT, copyright Cyril Cril 2026) and CHANGELOG.md**

`CHANGELOG.md`:

```markdown
# Changelog

## v0.1.0 — 2026-07-25

Initial release.

- `HasOtps` trait: `issueOtp` / `verifyOtp` / `consumeOtp`, purpose-scoped via
  consumer-supplied enums implementing `OtpPurpose`
- bcrypt-hashed storage, CSPRNG generation (6-digit floor), 10-minute default expiry
- Rate limiting on both ends (issue and verify) plus a per-code attempts budget
- Optional context binding — codes bound to the address they were sent to
- `OtpIssued` / `OtpVerified` / `OtpVerificationFailed` events (codes never in payloads)
- Polymorphic: works with uuid and bigint model keys
- `MassPrunable` cleanup
```

Copy `LICENSE.md` from `~/Code/laravel-impersonate/LICENSE.md`, keeping the same holder.

- [ ] **Step 3: Write the README**

`README.md` must cover, in this order (write real prose, not stubs — the API examples below are the source of truth):

1. **What it is** — one paragraph: purpose-scoped, hashed, rate-limited OTPs; extracted-and-hardened from two production hand-rolls; why not Spatie/otpz/otpify (one line each, from the spec's "Alternatives" section).
2. **Install**:
   ```bash
   composer require thecyrilcril/laravel-otp
   php artisan vendor:publish --tag=otp-migrations
   php artisan vendor:publish --tag=otp-config   # optional
   php artisan migrate
   ```
3. **Setup** — define a purpose enum + add the trait:
   ```php
   use Thecyrilcril\Otp\Contracts\OtpPurpose;

   enum Purpose: string implements OtpPurpose
   {
       case EmailVerification = 'email_verification';
       case PhoneVerification = 'phone_verification';

       public function value(): string
       {
           return $this->value;
       }
   }

   // On the model:
   use Thecyrilcril\Otp\Concerns\HasOtps;
   ```
4. **Usage** — issue (feed `$issued->code` into *your* notification; the package never sends), verify vs consume, context binding for phone/email-change flows (show the phone A/B swap attack it prevents, two sentences), `OtpThrottledException` handling with `retryAfterSeconds`.
5. **Security model** — the table from the spec's "Security controls" section, condensed: hashed at rest, check order, both-ends limiting, per-code budget, single-use, enumeration-resistant, context binding, `#[SensitiveParameter]`.
6. **Events** — the three events and the failure-reason enum; note codes never appear in payloads.
7. **Configuration** — the config block with defaults.
8. **Scheduling cleanup** — `$schedule->command('model:prune', ['--model' => [\Thecyrilcril\Otp\Models\Otp::class]])->daily();`
9. **Migration guide sketch** — for binitng-style hand-rolls: map `sendEmailVerificationOtp()` → `issueOtp(...)` + own notification; `verifyOtp(purpose, code)` keeps its name but codes become hashed (existing plaintext/encrypted rows cannot be migrated — expire them); add the two rate limits "for free".
10. **Versioning note** — 0.x until the first consumer migration proves the API; breaking changes possible before 1.0.

- [ ] **Step 4: Full gate, commit**

```bash
composer ci
git add -A
git commit -m "docs: add README, changelog, license and CI workflow"
```

---

### Task 9: Publish (USER CHECKPOINT — outward-facing)

**Files:** none (repo operations only)

- [ ] **Step 1: Create the GitHub repository and push** — ASK THE USER FIRST (public repo creation is outward-facing):

```bash
gh repo create thecyrilcril/laravel-otp --public --source=. --push
```

- [ ] **Step 2: Verify CI is green on GitHub**

Run: `gh run watch` (or check the Actions tab). Expected: the matrix (Laravel 12.*, 13.*) passes.

- [ ] **Step 3: Tag v0.1.0** — only after CI is green:

```bash
git tag v0.1.0
git push origin v0.1.0
```

- [ ] **Step 4: Submit to Packagist** — USER ACTION: submit `https://github.com/thecyrilcril/laravel-otp` at packagist.org/packages/submit (same account as laravel-impersonate), then enable the GitHub hook for auto-updates. Verify `composer require thecyrilcril/laravel-otp` resolves in a scratch project.

---

## Self-Review (performed at write time)

**Spec coverage:** D1 scope → Tasks 1–9 build only the package. D2 morphs → Task 2 schema + both-key-type tests (Tasks 2, 6). D3 consumer delivery → `IssuedOtp` return, no mail code anywhere. D4 Approach A → trait + `CodeGenerator`/`OtpLimiter` services. D5 context → Tasks 5–7 issue/verify/consume + A/B attack test. D6 hashed cast → Task 2 model + raw-original assertions. D7 matrix → composer.json + CI matrix. All 12 security controls have named homes and tests (floor-of-6: Task 3+5; storage: Task 2; check order: Task 6 impl; enumeration: Task 6 "bare false" test; verify limiting + per-row budget: Tasks 4, 6; issue limiting: Tasks 4, 5; single-use/race: Task 6 + hardening note; expiry: Tasks 2, 6, 7 boundary test; pruning: Task 2; purpose scoping: Tasks 5, 6, 7; context: Tasks 5–7; secrets hygiene: Tasks 3, 6, 7 leak test). Events + reasons: Tasks 3, 6. Config surface: Task 1. README/CI/release: Tasks 8–9.

**Placeholder scan:** README steps in Task 8 specify content per section rather than full prose — deliberate (prose duplicating the spec would go stale); every API example shown is complete and real. No TBDs.

**Type consistency:** `issueOtp(OtpPurpose, ?string): IssuedOtp`, `verifyOtp`/`consumeOtp(OtpPurpose, string, ?string): bool` consistent across Tasks 5–7 and README. `OtpLimiter` method names (`guardIssue`, `guardVerify`, `recordFailure`, `clear`) consistent between Tasks 4 and 6. `FailureReason` cases match between Tasks 3 and 6. `TestPurpose` fixture defined once (Task 2), used in 4–7.

**Known judgment calls encoded:** verify-throttle also throws (Global Constraints); `verifyOtp` non-destructive-on-success wording from the spec's self-review; no flaky parallelism test (hardening note); coverage bar 90% (impersonate's bar — kitwire's 100% gate is an app convention, not this package's).
