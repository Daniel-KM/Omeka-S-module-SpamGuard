<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\DnsMx;
use PHPUnit\Framework\TestCase;

class DnsMxTest extends TestCase
{
    public function testMissingEmailReturnsNull(): void
    {
        $s = new DnsMx(fn ($domain) => true);
        $this->assertNull($s->check(new SpamContext(), []));
    }

    public function testDomainWithoutMxIsFlagged(): void
    {
        $s = new DnsMx(fn ($domain) => false);
        $r = $s->check(new SpamContext(email: 'user@nomx.example'), []);
        $this->assertIsArray($r);
        $this->assertSame('dnsMx', $r['reason']);
        $this->assertSame(['domain' => 'nomx.example'], $r['detail']);
    }

    public function testDomainWithMxPasses(): void
    {
        $s = new DnsMx(fn ($domain) => true);
        $this->assertNull($s->check(new SpamContext(email: 'user@ok.example'), []));
    }

    /**
     * The calling module may disable the check with its own option.
     */
    public function testCallerCanDisableTheCheck(): void
    {
        $s = new DnsMx(fn ($domain) => false);
        $this->assertNull($s->check(new SpamContext(email: 'user@nomx.example', extra: ['checkDnsMx' => false]), []));
        $this->assertIsArray($s->check(new SpamContext(email: 'user@nomx.example', extra: ['checkDnsMx' => true]), []));
    }
}
