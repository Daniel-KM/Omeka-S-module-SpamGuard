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

    /**
     * @dataProvider answerProvider
     */
    public function testAnswerOfTheList(array $answers, bool $listed): void
    {
        $s = new Dnsbl(fn ($q) => $answers);
        $r = $s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => ['zen.spamhaus.org']]);
        $listed ? $this->assertIsArray($r) : $this->assertNull($r);
    }

    /**
     * @dataProvider policyCodeProvider
     */
    public function testPolicyCodesAreIgnoredForSpamhausOnly(string $zone, bool $listed): void
    {
        $s = new Dnsbl(fn ($q) => ['127.0.0.10']);
        $r = $s->check(new SpamContext(ip: '1.2.3.4'), ['zones' => [$zone]]);
        $listed ? $this->assertIsArray($r) : $this->assertNull($r);
    }

    public function policyCodeProvider(): array
    {
        return [
            'spamhaus zen' => ['zen.spamhaus.org', false],
            'spamhaus dqs' => ['key.zen.dq.spamhaus.net', false],
            'other list' => ['dnsbl.sorbs.net', true],
            'lookalike domain' => ['zen.notspamhaus.org', true],
        ];
    }

    public function answerProvider(): array
    {
        return [
            'listed sbl' => [['127.0.0.2'], true],
            'listed xbl' => [['127.0.0.4'], true],
            'listed among others' => [['127.255.255.254', '127.0.0.10'], true],
            'not listed' => [[], false],
            'public resolver refused' => [['127.255.255.254'], false],
            'quota exceeded' => [['127.255.255.255'], false],
            'typo in query' => [['127.255.255.252'], false],
            'loopback' => [['127.0.0.1'], false],
            'unrelated address' => [['8.8.8.8'], false],
        ];
    }
}
