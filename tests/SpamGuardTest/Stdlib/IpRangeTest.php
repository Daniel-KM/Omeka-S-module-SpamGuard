<?php declare(strict_types=1);

namespace SpamGuardTest\Stdlib;

use PHPUnit\Framework\TestCase;
use SpamGuard\Stdlib\IpRange;

class IpRangeTest extends TestCase
{
    /**
     * @dataProvider containsProvider
     */
    public function testContains(string $ip, string $entry, bool $expected): void
    {
        $this->assertSame($expected, IpRange::contains($ip, $entry));
    }

    public function containsProvider(): array
    {
        return [
            'exact ip' => ['192.0.2.10', '192.0.2.10', true],
            'other ip' => ['192.0.2.11', '192.0.2.10', false],
            'range /24' => ['192.0.2.200', '192.0.2.0/24', true],
            'out of range /24' => ['192.0.3.1', '192.0.2.0/24', false],
            'range /20 partial byte' => ['198.51.111.5', '198.51.96.0/20', true],
            'out of range /20' => ['198.51.112.5', '198.51.96.0/20', false],
            'range /0' => ['203.0.113.1', '0.0.0.0/0', true],
            'invalid mask' => ['192.0.2.10', '192.0.2.0/33', false],
            'ipv6 range' => ['2001:db8::42', '2001:db8::/32', true],
            'ipv6 out of range' => ['2001:db9::42', '2001:db8::/32', false],
            'ipv4 against ipv6 range' => ['192.0.2.10', '2001:db8::/32', false],
            'spaces' => ['192.0.2.10', '  192.0.2.0/24  ', true],
            'empty entry' => ['192.0.2.10', '', false],
            'invalid ip' => ['not-an-ip', '192.0.2.0/24', false],
        ];
    }

    public function testContainsAny(): void
    {
        $this->assertTrue(IpRange::containsAny('192.0.2.10', ['', '198.51.100.0/24', '192.0.2.0/24']));
        $this->assertFalse(IpRange::containsAny('192.0.2.10', ['198.51.100.0/24']));
        $this->assertFalse(IpRange::containsAny('192.0.2.10', []));
    }
}
