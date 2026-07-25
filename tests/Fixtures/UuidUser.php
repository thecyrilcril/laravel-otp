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
