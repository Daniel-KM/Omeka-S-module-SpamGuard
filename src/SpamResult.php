<?php declare(strict_types=1);

namespace SpamGuard;

final class SpamResult
{
    /**
     * Reasons reliable enough to be certain on their own: they come from the
     * content, the ip or a trap, not from timing or session state, so one of
     * them makes the submission a spam. The proof of work is one of them: it is
     * the only barrier against the bots that do not run javascript, and the
     * calling module may skip it for the visitors who cannot solve it.
     */
    const STRONG_REASONS = [
        'admin',
        'bannedIp',
        'dnsbl',
        'honeypot',
        'ipReputation',
        'keyword',
        'linkTld',
        'powChallenge',
        'url',
        'urlCount',
    ];

    /**
     * Weight of a weak reason (timing, session, dns of the sender domain): a
     * false positive is plausible, so one of them is a hint only and two are
     * needed to make a spam.
     */
    const WEAK_WEIGHT = 1;

    const STRONG_WEIGHT = 2;

    /**
     * Score from which the submission is a spam: a strong reason, or two weak.
     */
    const SPAM_SCORE = 2;

    public function __construct(
        public readonly array $reasons,
        public readonly array $details = [],
    ) {
    }

    public function isSpam(): bool
    {
        return $this->score() >= self::SPAM_SCORE;
    }

    /**
     * Is the verdict backed by a strong reason, so unlikely a false positive?
     */
    public function isCertain(): bool
    {
        return (bool) array_intersect($this->reasons, self::STRONG_REASONS);
    }

    public function score(): int
    {
        $score = 0;
        foreach (array_unique($this->reasons) as $reason) {
            $score += in_array($reason, self::STRONG_REASONS, true) ? self::STRONG_WEIGHT : self::WEAK_WEIGHT;
        }
        return $score;
    }

    public function reasonList(): string
    {
        return implode(',', $this->reasons);
    }
}
