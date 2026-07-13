<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

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
            if ($this->matches($ip, $entry)) {
                return $this->match('bannedIp', $entry);
            }
        }
        return null;
    }

    private function matches(string $ip, string $entry): bool
    {
        if (!str_contains($entry, '/')) {
            return $ip === $entry;
        }
        [$subnet, $bits] = explode('/', $entry, 2);
        $bits = (int) $bits;
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }
        $bytes = (int) ceil($bits / 8);
        $cmp = substr($ipBin, 0, $bytes) === substr($subnetBin, 0, $bytes);
        if (!$cmp || $bits % 8 === 0) {
            return $cmp;
        }
        $mask = chr(0xFF << (8 - ($bits % 8)) & 0xFF);
        return (ord($ipBin[$bytes - 1]) & ord($mask)) === (ord($subnetBin[$bytes - 1]) & ord($mask))
            && substr($ipBin, 0, $bytes - 1) === substr($subnetBin, 0, $bytes - 1);
    }
}
