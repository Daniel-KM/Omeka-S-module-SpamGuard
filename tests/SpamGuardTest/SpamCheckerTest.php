<?php declare(strict_types=1);

namespace SpamGuardTest;

use SpamGuard\SpamChecker;
use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\Honeypot;
use SpamGuard\SpamStrategy\Keyword;
use SpamGuard\SpamStrategy\SpamStrategyManager;
use Laminas\ServiceManager\ServiceManager;
use PHPUnit\Framework\TestCase;

class SpamCheckerTest extends TestCase
{
    private function manager(): SpamStrategyManager
    {
        return new SpamStrategyManager(new ServiceManager(), [
            'invokables' => [
                'honeypot' => Honeypot::class,
                'keyword' => Keyword::class,
            ],
        ]);
    }

    public function testCleanContextReturnsNotSpam(): void
    {
        $c = new SpamChecker($this->manager(), ['honeypot'], []);
        $r = $c->check(new SpamContext(honeypotValue: ''));
        $this->assertFalse($r->isSpam());
    }

    public function testCollectsAllReasonsWhenMultipleStrategiesFail(): void
    {
        $c = new SpamChecker($this->manager(), ['honeypot', 'keyword'], []);
        $r = $c->check(new SpamContext(
            body: 'crypto-pump offer',
            honeypotValue: 'bot',
        ));
        $this->assertTrue($r->isSpam());
        $this->assertContains('honeypot', $r->reasons);
        $this->assertContains('keyword', $r->reasons);
    }

    public function testDisabledStrategyIsSkipped(): void
    {
        $c = new SpamChecker($this->manager(), ['keyword'], []);
        $r = $c->check(new SpamContext(honeypotValue: 'bot', body: 'hello'));
        $this->assertFalse($r->isSpam());
    }
}
