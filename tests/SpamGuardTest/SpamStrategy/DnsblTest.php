<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\Dnsbl;
use PHPUnit\Framework\TestCase;

class DnsblTest extends TestCase
{
    public function testMissingIpReturnsNull(): void
    {
        $s = new Dnsbl(fn ($q) => true);
        $this->assertNull($s->check(new SpamContext(), ['zones' => ['zen.spamhaus.org']]));
    }

    public function testNoZonesReturnsNull(): void
    {
        $s = new Dnsbl(fn ($q) => true);
        $this->assertNull($s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => []]));
    }

    public function testListedIpIsFlagged(): void
    {
        $s = new Dnsbl(fn ($q) => $q === '4.3.2.1.zen.spamhaus.org');
        $r = $s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => ['zen.spamhaus.org']]);
        $this->assertIsArray($r);
        $this->assertSame('dnsbl', $r['reason']);
        $this->assertSame(['zone' => 'zen.spamhaus.org'], $r['detail']);
    }

    public function testSecondZoneHitReturnsCorrectZone(): void
    {
        $s = new Dnsbl(fn ($q) => $q === '4.3.2.1.bl.example.org');
        $r = $s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => ['zen.spamhaus.org', 'bl.example.org']]);
        $this->assertIsArray($r);
        $this->assertSame('dnsbl', $r['reason']);
        $this->assertSame(['zone' => 'bl.example.org'], $r['detail']);
    }

    public function testUnlistedIpReturnsNull(): void
    {
        $s = new Dnsbl(fn ($q) => false);
        $this->assertNull($s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => ['zen.spamhaus.org', 'bl.example.org']]));
    }

    public function testIpv6ReturnsNull(): void
    {
        $called = false;
        $s = new Dnsbl(function ($q) use (&$called) { $called = true; return true; });
        $this->assertNull($s->check(new SpamContext(ip: '2001:db8::1'), ['zones' => ['zen.spamhaus.org']]));
        $this->assertFalse($called);
    }
}
