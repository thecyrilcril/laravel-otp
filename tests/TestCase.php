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

        // No-ops on sqlite :memory: (fresh database per test); on MySQL they
        // make each test start clean, since the schema persists between tests.
        // The migrations ledger is dropped too so loadMigrationsFrom() below
        // re-runs the otps migration every test instead of trusting a stale
        // "already ran" record against a table we just dropped.
        Schema::dropIfExists('otps');
        Schema::dropIfExists('migrations');
        Schema::dropIfExists('int_users');
        Schema::dropIfExists('users');

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

    /**
     * Defaults to in-memory sqlite. Set DB_CONNECTION=mysql (with the usual
     * DB_* variables) to run the identical suite against a real concurrent
     * engine, so the compare-and-delete consume path and the atomic attempts
     * bookkeeping are exercised for real — sqlite cannot meaningfully model
     * concurrent writers. CI runs both.
     */
    protected function defineEnvironment($app): void
    {
        $config = $app['config'];

        $connection = env('DB_CONNECTION', 'testing');

        $config->set('database.default', $connection);
        $config->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        if ($connection === 'mysql') {
            $config->set('database.connections.mysql', [
                'driver' => 'mysql',
                'host' => env('DB_HOST', '127.0.0.1'),
                'port' => env('DB_PORT', '3306'),
                'database' => env('DB_DATABASE', 'otp_test'),
                'username' => env('DB_USERNAME', 'root'),
                'password' => env('DB_PASSWORD', ''),
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
                'strict' => true,
            ]);
        }

        $config->set('cache.default', 'array');
    }
}
