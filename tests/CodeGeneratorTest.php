<?php

declare(strict_types=1);

use Thecyrilcril\Otp\Support\CodeGenerator;

it('generates codes of the requested length, digits only, zero-padded', function (): void {
    $generator = new CodeGenerator;

    foreach (range(1, 50) as $i) {
        $code = $generator->generate(6);
        expect(strlen($code))->toBe(6);
        expect(ctype_digit($code))->toBeTrue();
    }

    $long = $generator->generate(8);
    expect(strlen($long))->toBe(8)
        ->and(ctype_digit($long))->toBeTrue();
});

it('refuses lengths below six', function (): void {
    (new CodeGenerator)->generate(4);
})->throws(InvalidArgumentException::class, 'at least 6');

it('refuses lengths above ten', function (): void {
    (new CodeGenerator)->generate(19);
})->throws(InvalidArgumentException::class, 'at most 10');
