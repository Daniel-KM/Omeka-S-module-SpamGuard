<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\UrlCount;
use PHPUnit\Framework\TestCase;

class UrlCountTest extends TestCase
{
    public function testBelowThresholdPasses(): void
    {
        $s = new UrlCount();
        $body = 'See https://a.example and http://b.example for details.';
        $this->assertNull($s->check(new SpamContext(body: $body), ['maxUrls' => 3]));
    }

    public function testAboveThresholdFlags(): void
    {
        $s = new UrlCount();
        $body = 'https://a.example https://b.example http://c.example https://d.example';
        $r = $s->check(new SpamContext(body: $body), ['maxUrls' => 3]);
        $this->assertIsArray($r);
        $this->assertSame('urlCount', $r['reason']);
        $this->assertSame(['count' => 4], $r['detail']);
    }
}
