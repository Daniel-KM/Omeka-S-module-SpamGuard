<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\Stdlib\IpRange;

class BannedIp extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        $ip = $context->ip;
        if (!$ip) {
            return null;
        }
        $bans = (array) ($settings['bannedIps'] ?? []);
        foreach ($bans as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (IpRange::contains($ip, $entry)) {
                return $this->match('bannedIp', $entry);
            }
        }
        return null;
    }
}
