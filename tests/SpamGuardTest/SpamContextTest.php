<?php declare(strict_types=1);

namespace SpamGuardTest;

use SpamGuard\SpamContext;
use PHPUnit\Framework\TestCase;

class SpamContextTest extends TestCase
{
    public function testContextStoresAllFields(): void
    {
        $ctx = new SpamContext(
            ip: '1.2.3.4',
            userAgent: 'Mozilla/5.0',
            email: 'x@y.z',
            subject: 'Hello',
            body: 'World',
            formLoadedAt: 1700000000,
            honeypotValue: '',
            userId: null,
            extra: ['source' => 'contact-us'],
        );

        $this->assertSame('1.2.3.4', $ctx->ip);
        $this->assertSame('Mozilla/5.0', $ctx->userAgent);
        $this->assertSame('contact-us', $ctx->extra['source']);
        $this->assertNull($ctx->userId);
    }
}
