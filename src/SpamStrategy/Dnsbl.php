<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class Dnsbl extends AbstractSpamStrategy
{
    /**
     * Last byte of the answers of the Spamhaus policy block list (PBL).
     *
     * The codes are specific to Spamhaus: other lists use them for other
     * meanings, so they are ignored for the Spamhaus zones only.
     */
    const POLICY_CODES = [10, 11];

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
            if ($this->isListed(($this->resolver)($reverse . '.' . $zone), $zone)) {
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
     * For a Spamhaus zone, the codes 127.0.0.10 and 127.0.0.11 are the policy
     * block list (PBL), included in "zen": it lists the dynamic ranges of
     * consumer access providers, that should not send mail directly, but it is
     * not a sign of spam for a visitor of a site, so it is ignored.
     *
     * @param array|bool $answers
     */
    private function isListed($answers, string $zone = ''): bool
    {
        $ignored = preg_match('~(^|\.)spamhaus\.(org|net)$~i', $zone) ? self::POLICY_CODES : [];
        if (is_bool($answers)) {
            return $answers;
        }
        foreach ((array) $answers as $answer) {
            if (preg_match('~^127\.0\.0\.(\d{1,3})$~', (string) $answer, $m)
                && (int) $m[1] >= 2
                && (int) $m[1] <= 255
                && !in_array((int) $m[1], $ignored, true)
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
