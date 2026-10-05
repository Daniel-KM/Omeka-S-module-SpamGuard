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

    public function testOneStrongReasonIsSpamAndCertain(): void
    {
        $r = new SpamResult(['honeypot']);
        $this->assertTrue($r->isSpam());
        $this->assertTrue($r->isCertain());
        $this->assertSame(2, $r->score());
    }

    public function testOneWeakReasonIsOnlyAHint(): void
    {
        foreach (['tooFast', 'rateLimit', 'dnsMx'] as $weak) {
            $r = new SpamResult([$weak]);
            $this->assertFalse($r->isSpam(), $weak);
            $this->assertFalse($r->isCertain(), $weak);
            $this->assertSame(1, $r->score(), $weak);
        }
    }

    public function testFailedProofOfWorkAloneIsSpam(): void
    {
        $this->assertTrue((new SpamResult(['powChallenge']))->isSpam());
    }

    public function testTwoWeakReasonsAreSpamButNotCertain(): void
    {
        $r = new SpamResult(['tooFast', 'dnsMx']);
        $this->assertTrue($r->isSpam());
        $this->assertFalse($r->isCertain());
    }

    public function testDuplicatedReasonCountsOnce(): void
    {
        $this->assertFalse((new SpamResult(['tooFast', 'tooFast']))->isSpam());
    }
}
