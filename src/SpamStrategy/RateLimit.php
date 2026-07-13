<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class RateLimit extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        $lastSubmitAt = $context->extra['lastSubmitAt'] ?? null;
        if ($lastSubmitAt === null) {
            return null;
        }
        $lastSubmitIp = $context->extra['lastSubmitIp'] ?? null;
        if ($lastSubmitIp !== null && $lastSubmitIp !== $context->ip) {
            return null;
        }
        $now = $context->extra['now'] ?? time();
        $minInterval = (int) ($settings['minInterval'] ?? 10);
        $elapsed = (int) $now - (int) $lastSubmitAt;
        if ($elapsed < $minInterval) {
            return $this->match('rateLimit', ['elapsed' => $elapsed, 'minInterval' => $minInterval]);
        }
        return null;
    }
}
