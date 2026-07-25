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
