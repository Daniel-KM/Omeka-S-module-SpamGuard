<?php declare(strict_types=1);

namespace SpamGuardTest\Stdlib;

use SpamGuard\Stdlib\FormToken;
use PHPUnit\Framework\TestCase;

class FormTokenTest extends TestCase
{
    const IP = '192.0.2.10';

    protected function token(): FormToken
    {
        return new FormToken('secret-of-test');
    }

    public function testTokenCarriesTheTimeAndTheSalt(): void
    {
        $now = 1700000000;
        $token = $this->token()->issue('abcdef0123', self::IP, $now);
        $this->assertSame(
            ['issuedAt' => $now, 'salt' => 'abcdef0123'],
            $this->token()->read($token, self::IP, $now + 30)
        );
    }

    /**
     * A visitor may take hours to write a message: the token remains valid,
     * unlike the session of php, that expires after 24 minutes by default.
     */
    public function testTokenRemainsValidForHours(): void
    {
        $now = 1700000000;
        $token = $this->token()->issue('abcdef', self::IP, $now);
        $this->assertNotNull($this->token()->read($token, self::IP, $now + 3 * 3600));
        $this->assertNotNull($this->token()->read($token, self::IP, $now + FormToken::MAX_AGE));
        $this->assertNull($this->token()->read($token, self::IP, $now + FormToken::MAX_AGE + 1));
    }

    /**
     * The salt is empty when the proof-of-work is skipped: the token still
     * carries the time of display.
     */
    public function testTokenWithoutSalt(): void
    {
        $now = 1700000000;
        $token = $this->token()->issue('', self::IP, $now);
        $this->assertSame(['issuedAt' => $now, 'salt' => ''], $this->token()->read($token, self::IP, $now));
    }

    public function testTokenIsBoundToTheIp(): void
    {
        $token = $this->token()->issue('abcdef', self::IP);
        $this->assertNull($this->token()->read($token, '192.0.2.11'));
    }

    public function testTokenSignedWithAnotherSecretIsRejected(): void
    {
        $token = (new FormToken('other-secret'))->issue('abcdef', self::IP);
        $this->assertNull($this->token()->read($token, self::IP));
    }

    /**
     * A bot cannot back-date the token to pass the check of the delay.
     */
    public function testForgedTimeOrSaltIsRejected(): void
    {
        $now = 1700000000;
        [$issuedAt, $salt, $signature] = explode('.', $this->token()->issue('abcdef', self::IP, $now));
        $this->assertNull($this->token()->read(($issuedAt - 60) . '.' . $salt . '.' . $signature, self::IP, $now));
        $this->assertNull($this->token()->read($issuedAt . '.abcdee.' . $signature, self::IP, $now));
    }

    public function testTokenFromTheFutureIsRejected(): void
    {
        $now = 1700000000;
        $token = $this->token()->issue('abcdef', self::IP, $now + 600);
        $this->assertNull($this->token()->read($token, self::IP, $now));
    }

    /**
     * @dataProvider malformedProvider
     */
    public function testMalformedTokenIsRejected(?string $token): void
    {
        $this->assertNull($this->token()->read($token, self::IP));
    }

    public function malformedProvider(): array
    {
        return [
            'null' => [null],
            'empty' => [''],
            'two parts' => ['1700000000.abcdef'],
            'four parts' => ['1700000000.abcdef.sig.more'],
            'time not numeric' => ['17000x0000.abcdef.sig'],
            'salt not hexadecimal' => ['1700000000.<script>.sig'],
        ];
    }
}
