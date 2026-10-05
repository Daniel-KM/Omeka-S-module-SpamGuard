<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class Dnsbl extends AbstractSpamStrategy
{
    /** @var callable */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver ?? static fn (string $query): array => array_column(
            (array) (@dns_get_record($query, DNS_A) ?: []),
            'ip'
        );
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
            if ($this->isListed(($this->resolver)($reverse . '.' . $zone))) {
                return $this->match('dnsbl', ['zone' => $zone]);
            }
        }
        return null;
    }

    /**
     * Is one of the answers of the dnsbl an actual listing?
     *
     * A listing is an address 127.0.0.2 to 127.0.0.255. The lists answer with
     * other addresses to report an error, for example Spamhaus with
     * 127.255.255.254 when queried through a public resolver, or
     * 127.255.255.255 when the quota is exceeded: such an answer must not mark
     * every message as spam. A resolver returning a boolean is kept for
     * compatibility.
     *
     * @param array|bool $answers
     */
    private function isListed($answers): bool
    {
        if (is_bool($answers)) {
            return $answers;
        }
        foreach ((array) $answers as $answer) {
            if (preg_match('~^127\.0\.0\.(\d{1,3})$~', (string) $answer, $m)
                && (int) $m[1] >= 2
                && (int) $m[1] <= 255
            ) {
                return true;
            }
        }
        return false;
    }

    private function reverseIp(string $ip): ?string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }
        return implode('.', array_reverse(explode('.', $ip)));
    }
}
