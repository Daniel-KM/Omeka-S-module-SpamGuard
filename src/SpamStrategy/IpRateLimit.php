<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamLog;
use SpamGuard\Stdlib\IpRange;

/**
 * Too many submissions from the same ip in a short time, whatever the session.
 *
 * The rate limit by session is defeated by a bot that drops its cookie, so
 * this one counts the submissions recorded in the journal by all the modules.
 * The threshold is high, since the visitors of an institution may share a few
 * public ips, that can be listed as trusted anyway.
 */
class IpRateLimit extends AbstractSpamStrategy
{
    /**
     * @var \SpamGuard\SpamLog|null
     */
    protected $spamLog;

    public function __construct(?SpamLog $spamLog = null)
    {
        $this->spamLog = $spamLog;
    }

    public function check(SpamContext $context, array $settings): ?array
    {
        $ip = (string) ($context->ip ?? '');
        $max = (int) ($settings['maxCount'] ?? 10);
        $minutes = (int) ($settings['minutes'] ?? 10);
        if (!$this->spamLog || $ip === '' || $max <= 0 || $minutes <= 0) {
            return null;
        }
        if (IpRange::containsAny($ip, (array) ($settings['trusted'] ?? []))) {
            return null;
        }
        $count = $this->spamLog->countRecent($ip, $minutes);
        if ($count >= $max) {
            return $this->match('ipRateLimit', ['count' => $count, 'max' => $max, 'minutes' => $minutes]);
        }
        return null;
    }
}
