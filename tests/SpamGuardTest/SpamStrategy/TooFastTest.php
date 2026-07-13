<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\TooFast;
use PHPUnit\Framework\TestCase;

class TooFastTest extends TestCase
{
    public function testSubmissionUnderDelayFlags(): void
    {
        $s = new TooFast();
        $now = time();
        $ctx = new SpamContext(formLoadedAt: $now, extra: ['now' => $now]);
        $r = $s->check($ctx, ['minDelay' => 1]);
        $this->assertSame('tooFast', $r['reason']);
    }

    public function testSubmissionAfterDelayPasses(): void
    {
        $s = new TooFast();
        $now = time();
        $ctx = new SpamContext(formLoadedAt: $now - 5, extra: ['now' => $now]);
        $this->assertNull($s->check($ctx, ['minDelay' => 1]));
    }

    public function testMissingTimestampPasses(): void
    {
        $s = new TooFast();
        $this->assertNull($s->check(new SpamContext(), ['minDelay' => 1]));
    }
}
