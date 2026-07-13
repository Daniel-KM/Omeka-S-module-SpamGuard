<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\Keyword;
use PHPUnit\Framework\TestCase;

class KeywordTest extends TestCase
{
    public function testCleanBodyPasses(): void
    {
        $s = new Keyword();
        $this->assertNull($s->check(new SpamContext(body: 'Bonjour, ceci est un message légitime.'), []));
    }

    public function testBodyWithSpamGuardKeywordFlags(): void
    {
        $s = new Keyword();
        $r = $s->check(new SpamContext(body: 'Join our crypto-pump group now!'), []);
        $this->assertIsArray($r);
        $this->assertSame('keyword', $r['reason']);
        $this->assertSame('crypto-pump', $r['detail']);
    }

    public function testSubjectWithKeywordFlags(): void
    {
        $s = new Keyword();
        $r = $s->check(new SpamContext(subject: 'Amazing crypto-pump offer', body: 'Hello'), []);
        $this->assertIsArray($r);
        $this->assertSame('keyword', $r['reason']);
    }
}
