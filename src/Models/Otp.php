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
        return self::query()->where('expires_at', '<', now());
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
