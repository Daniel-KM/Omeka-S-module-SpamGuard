<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\Honeypot;
use PHPUnit\Framework\TestCase;

class HoneypotTest extends TestCase
{
    public function testEmptyHoneypotPasses(): void
    {
        $s = new Honeypot();
        $this->assertNull($s->check(new SpamContext(honeypotValue: ''), []));
        $this->assertNull($s->check(new SpamContext(honeypotValue: null), []));
    }

    public function testFilledHoneypotFlags(): void
    {
        $s = new Honeypot();
        $r = $s->check(new SpamContext(honeypotValue: 'some-bot-value'), []);
        $this->assertSame('honeypot', $r['reason']);
        $this->assertSame('some-bot-value', $r['detail']);
    }
}
