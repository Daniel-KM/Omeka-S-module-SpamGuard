<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamLog;
use SpamGuard\Stdlib\IpRange;

/**
 * Flag a message sent from an ip that sent a spam recently, in any module.
 *
 * The checks on timing rely on the session or on the speed of the bot, so a
 * bot is caught one time out of two. The reputation reads the journal of the
 * verdicts, so it does not depend on them. To avoid blocking the visitors who
 * share an ip, only the spams detected by reliable checks count, the duration
 * is short, the trusted networks are never blocked, and a decision of an admin
 * that a message is not a spam cancels the previous ones.
 */
class IpReputation extends AbstractSpamStrategy
{
    /**
     * Reasons of a spam reliable enough to block the ip that sent it. The
     * checks based on timing or on the session produce false positives, and
     * the reputation itself is excluded, otherwise a visitor who retries after
     * a false positive would extend his own block forever.
     */
    const RELIABLE_REASONS = [
        'admin',
        'bannedIp',
        'dnsbl',
        'honeypot',
        'keyword',
        'linkTld',
        'url',
        'urlCount',
    ];

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
        $hours = (int) ($settings['hours'] ?? 24);
        if (!$this->spamLog || $ip === '' || $hours <= 0) {
            return null;
        }
        if (IpRange::containsAny($ip, (array) ($settings['trusted'] ?? []))) {
            return null;
        }
        if ($this->spamLog->hasRecentSpam($ip, $hours, self::RELIABLE_REASONS)) {
            return $this->match('ipReputation', ['hours' => $hours]);
        }
        return null;
    }
}
