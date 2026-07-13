<?php declare(strict_types=1);

namespace SpamGuardTest;

use SpamGuard\SpamResult;
use PHPUnit\Framework\TestCase;

class SpamResultTest extends TestCase
{
    public function testEmptyResultIsNotSpam(): void
    {
        $r = new SpamResult([], []);
        $this->assertFalse($r->isSpam());
        $this->assertSame('', $r->reasonList());
    }

    public function testPopulatedResultIsSpamAndSerialises(): void
    {
        $r = new SpamResult(['honeypot', 'tooFast'], ['keyword' => 'viagra']);
        $this->assertTrue($r->isSpam());
        $this->assertSame('honeypot,tooFast', $r->reasonList());
        $this->assertSame(['honeypot', 'tooFast'], $r->reasons);
        $this->assertSame(['keyword' => 'viagra'], $r->details);
    }
}
