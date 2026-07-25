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
