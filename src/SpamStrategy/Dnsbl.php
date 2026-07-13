<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class Dnsbl extends AbstractSpamStrategy
{
    /** @var callable */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver ?? static fn (string $query): bool => (bool) @dns_get_record($query, DNS_A);
    }

    public function check(SpamContext $context, array $settings): ?array
    {
        $ip = (string) ($context->ip ?? '');
        if ($ip === '') {
            return null;
        }
        $zones = (array) ($settings['zones'] ?? []);
        if (!$zones) {
            return null;
        }
        $reverse = $this->reverseIp($ip);
        if ($reverse === null) {
            return null;
        }
        foreach ($zones as $zone) {
            $zone = trim((string) $zone);
            if ($zone === '') {
                continue;
            }
            if (($this->resolver)($reverse . '.' . $zone)) {
                return $this->match('dnsbl', ['zone' => $zone]);
            }
        }
        return null;
    }

    private function reverseIp(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }
        return implode('.', array_reverse(explode('.', $ip)));
    }
}
