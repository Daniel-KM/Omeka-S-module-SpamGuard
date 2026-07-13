<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\RateLimit;
use PHPUnit\Framework\TestCase;

class RateLimitTest extends TestCase
{
    public function testNoPreviousSubmissionPasses(): void
    {
        $s = new RateLimit();
        $ctx = new SpamContext(ip: '1.2.3.4', extra: ['now' => 1000]);
        $this->assertNull($s->check($ctx, ['minInterval' => 10]));
    }

    public function testDifferentIpPasses(): void
    {
        $s = new RateLimit();
        $ctx = new SpamContext(ip: '1.2.3.4', extra: [
            'now' => 1000,
            'lastSubmitAt' => 995,
            'lastSubmitIp' => '5.6.7.8',
        ]);
        $this->assertNull($s->check($ctx, ['minInterval' => 10]));
    }

    public function testSameIpTooSoonFlags(): void
    {
        $s = new RateLimit();
        $ctx = new SpamContext(ip: '1.2.3.4', extra: [
            'now' => 1000,
            'lastSubmitAt' => 995,
            'lastSubmitIp' => '1.2.3.4',
        ]);
        $r = $s->check($ctx, ['minInterval' => 10]);
        $this->assertSame('rateLimit', $r['reason']);
        $this->assertSame(5, $r['detail']['elapsed']);
        $this->assertSame(10, $r['detail']['minInterval']);
    }

    public function testSameIpAfterIntervalPasses(): void
    {
        $s = new RateLimit();
        $ctx = new SpamContext(ip: '1.2.3.4', extra: [
            'now' => 1000,
            'lastSubmitAt' => 980,
            'lastSubmitIp' => '1.2.3.4',
        ]);
        $this->assertNull($s->check($ctx, ['minInterval' => 10]));
    }

    public function testLastSubmitAtWithoutIpAppliesLimit(): void
    {
        $s = new RateLimit();
        $ctx = new SpamContext(ip: '1.2.3.4', extra: [
            'now' => 1000,
            'lastSubmitAt' => 997,
        ]);
        $r = $s->check($ctx, ['minInterval' => 10]);
        $this->assertSame('rateLimit', $r['reason']);
    }
}
