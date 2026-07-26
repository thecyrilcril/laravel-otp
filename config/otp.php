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
    | verify_limit: verification attempts allowed per model+purpose within
    | the decay window (seconds). Counts every guarded attempt, not just
    | failures — a successful verify consumes one unit but is immediately
    | refunded, so legitimate users are unaffected.
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
