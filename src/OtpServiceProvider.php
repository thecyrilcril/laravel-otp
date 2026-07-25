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
