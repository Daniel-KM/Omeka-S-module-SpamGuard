<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\PowChallenge;
use PHPUnit\Framework\TestCase;

class PowChallengeTest extends TestCase
{
    private function solve(string $salt, int $difficulty): string
    {
        $prefix = str_repeat('0', $difficulty);
        for ($i = 0; $i < 1000000; $i++) {
            $nonce = (string) $i;
            if (substr(hash('sha256', $salt . ':' . $nonce), 0, $difficulty) === $prefix) {
                return $nonce;
            }
        }
        self::fail('Unable to solve PoW.');
    }

    public function testValidNoncePasses(): void
    {
        $s = new PowChallenge();
        $salt = 'abcdef0123456789abcdef0123456789';
        $nonce = $this->solve($salt, 2);
        $ctx = new SpamContext(extra: ['powSalt' => $salt, 'powNonce' => $nonce]);
        $this->assertNull($s->check($ctx, ['difficulty' => 2]));
    }

    public function testMissingSaltFlags(): void
    {
        $s = new PowChallenge();
        $ctx = new SpamContext(extra: ['powNonce' => '42']);
        $r = $s->check($ctx, ['difficulty' => 2]);
        $this->assertSame('powChallenge', $r['reason']);
        $this->assertSame('missing', $r['detail']);
    }

    public function testMissingNonceFlags(): void
    {
        $s = new PowChallenge();
        $ctx = new SpamContext(extra: ['powSalt' => 'abcdef0123456789abcdef0123456789']);
        $r = $s->check($ctx, ['difficulty' => 2]);
        $this->assertSame('powChallenge', $r['reason']);
        $this->assertSame('missing', $r['detail']);
    }

    public function testInvalidNonceFlags(): void
    {
        $s = new PowChallenge();
        $salt = 'abcdef0123456789abcdef0123456789';
        $ctx = new SpamContext(extra: ['powSalt' => $salt, 'powNonce' => 'not-a-valid-nonce-xyz']);
        $r = $s->check($ctx, ['difficulty' => 4]);
        $this->assertSame('powChallenge', $r['reason']);
        $this->assertSame('invalid', $r['detail']);
    }

    public function testNonceValidForLowerDifficultyFailsHigher(): void
    {
        $s = new PowChallenge();
        $salt = 'abcdef0123456789abcdef0123456789';
        $nonce = $this->solve($salt, 2);
        $hash = hash('sha256', $salt . ':' . $nonce);
        if (substr($hash, 0, 4) === '0000') {
            $this->markTestSkipped('Solved nonce happens to satisfy higher difficulty.');
        }
        $ctx = new SpamContext(extra: ['powSalt' => $salt, 'powNonce' => $nonce]);
        $r = $s->check($ctx, ['difficulty' => 4]);
        $this->assertSame('powChallenge', $r['reason']);
        $this->assertSame('invalid', $r['detail']);
    }
}
