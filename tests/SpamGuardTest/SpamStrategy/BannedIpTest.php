<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\BannedIp;
use PHPUnit\Framework\TestCase;

class BannedIpTest extends TestCase
{
    public function testExactMatchFlags(): void
    {
        $s = new BannedIp();
        $r = $s->check(new SpamContext(ip: '1.2.3.4'), ['bannedIps' => ['1.2.3.4']]);
        $this->assertSame('bannedIp', $r['reason']);
    }

    public function testCidrMatchFlags(): void
    {
        $s = new BannedIp();
        $r = $s->check(new SpamContext(ip: '10.0.0.5'), ['bannedIps' => ['10.0.0.0/24']]);
        $this->assertSame('bannedIp', $r['reason']);
    }

    public function testNoMatchPasses(): void
    {
        $s = new BannedIp();
        $this->assertNull($s->check(new SpamContext(ip: '8.8.8.8'), ['bannedIps' => ['1.2.3.4', '10.0.0.0/24']]));
    }

    public function testMissingIpPasses(): void
    {
        $s = new BannedIp();
        $this->assertNull($s->check(new SpamContext(), ['bannedIps' => ['1.2.3.4']]));
    }
}
