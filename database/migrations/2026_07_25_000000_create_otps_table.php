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
