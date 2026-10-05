<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use PHPUnit\Framework\TestCase;
use SpamGuard\SpamContext;
use SpamGuard\SpamLog;
use SpamGuard\SpamStrategy\IpReputation;

class IpReputationTest extends TestCase
{
    protected function strategy(bool $hasRecentSpam, ?array &$calls = null): IpReputation
    {
        $log = $this->createMock(SpamLog::class);
        $log->method('hasRecentSpam')->willReturnCallback(
            function ($ip, $hours, $reasons) use ($hasRecentSpam, &$calls) {
                $calls[] = [$ip, $hours, $reasons];
                return $hasRecentSpam;
            }
        );
        return new IpReputation($log);
    }

    public function testIpWithRecentSpamIsFlagged(): void
    {
        $r = $this->strategy(true)->check(new SpamContext(ip: '203.0.113.7'), ['hours' => 24]);
        $this->assertSame('ipReputation', $r['reason']);
        $this->assertSame(['hours' => 24], $r['detail']);
    }

    public function testIpWithoutRecentSpamPasses(): void
    {
        $this->assertNull($this->strategy(false)->check(new SpamContext(ip: '203.0.113.7'), ['hours' => 24]));
    }

    /**
     * Only the reliable reasons are asked to the journal, and never the
     * reputation itself, so a retry after a false positive does not extend
     * the block.
     */
    public function testOnlyReliableReasonsAreAsked(): void
    {
        $calls = [];
        $this->strategy(false, $calls)->check(new SpamContext(ip: '203.0.113.7'), ['hours' => 6]);
        [, $hours, $reasons] = $calls[0];
        $this->assertSame(6, $hours);
        $this->assertContains('keyword', $reasons);
        $this->assertContains('admin', $reasons);
        foreach (['tooFast', 'tooSlow', 'rateLimit', 'powChallenge', 'ipReputation', 'captcha'] as $fragile) {
            $this->assertNotContains($fragile, $reasons);
        }
    }

    public function testTrustedNetworkIsNeverBlocked(): void
    {
        $calls = [];
        $r = $this->strategy(true, $calls)->check(
            new SpamContext(ip: '192.0.2.10'),
            ['hours' => 24, 'trusted' => ['192.0.2.0/24']]
        );
        $this->assertNull($r);
        $this->assertSame([], (array) $calls);
    }

    public function testZeroHoursOrMissingIpOrJournalDisablesTheCheck(): void
    {
        $this->assertNull($this->strategy(true)->check(new SpamContext(ip: '203.0.113.7'), ['hours' => 0]));
        $this->assertNull($this->strategy(true)->check(new SpamContext(), ['hours' => 24]));
        $this->assertNull((new IpReputation())->check(new SpamContext(ip: '203.0.113.7'), ['hours' => 24]));
    }
}
