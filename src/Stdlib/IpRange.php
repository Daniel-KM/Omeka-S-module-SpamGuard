<?php declare(strict_types=1);

namespace SpamGuard\Stdlib;

class IpRange
{
    /**
     * Is the ip equal to the entry or inside the range (cidr) of the entry?
     *
     * Ipv4 and ipv6 are supported. An ip never matches a range of the other
     * family.
     */
    public static function contains(string $ip, string $entry): bool
    {
        $entry = trim($entry);
        $ipBin = @inet_pton($ip);
        if ($entry === '' || $ipBin === false) {
            return false;
        }
        [$subnet, $bits] = array_pad(explode('/', $entry, 2), 2, null);
        $subnetBin = @inet_pton($subnet);
        if ($subnetBin === false || strlen($subnetBin) !== strlen($ipBin)) {
            return false;
        }
        $bits = $bits === null ? strlen($ipBin) * 8 : (int) $bits;
        if ($bits < 0 || $bits > strlen($ipBin) * 8) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if (substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }

    /**
     * Is the ip inside one of the entries?
     */
    public static function containsAny(string $ip, array $entries): bool
    {
        foreach ($entries as $entry) {
            if (self::contains($ip, (string) $entry)) {
                return true;
            }
        }
        return false;
    }
}
