<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use PHPUnit\Framework\TestCase;
use SpamGuard\SpamContext;
use SpamGuard\SpamLog;
use SpamGuard\SpamStrategy\IpRateLimit;

class IpRateLimitTest extends TestCase
{
    private function strategy(int $count): IpRateLimit
    {
        $log = $this->createMock(SpamLog::class);
        $log->method('countRecent')->willReturn($count);
        return new IpRateLimit($log);
    }

    public function testBelowThresholdIsNotSpam(): void
    {
        $r = $this->strategy(9)->check(new SpamContext(ip: '203.0.113.7'), ['maxCount' => 10, 'minutes' => 10]);
        $this->assertNull($r);
    }

    public function testThresholdReachedIsSpam(): void
    {
        $r = $this->strategy(10)->check(new SpamContext(ip: '203.0.113.7'), ['maxCount' => 10, 'minutes' => 10]);
        $this->assertIsArray($r);
        $this->assertSame('ipRateLimit', $r['reason']);
        $this->assertSame(10, $r['detail']['count']);
    }

    public function testTrustedIpIsNeverLimited(): void
    {
        $r = $this->strategy(100)->check(
            new SpamContext(ip: '203.0.113.7'),
            ['maxCount' => 10, 'minutes' => 10, 'trusted' => ['203.0.113.0/24']]
        );
        $this->assertNull($r);
    }

    public function testDisabledByZeroOrWithoutLog(): void
    {
        $this->assertNull($this->strategy(100)->check(new SpamContext(ip: '203.0.113.7'), ['maxCount' => 0]));
        $this->assertNull((new IpRateLimit())->check(new SpamContext(ip: '203.0.113.7'), ['maxCount' => 1]));
    }
}
