<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class TooFast extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        if ($context->formLoadedAt === null) {
            return null;
        }
        $now = $context->extra['now'] ?? time();
        $elapsed = $now - $context->formLoadedAt;
        $min = (int) ($settings['minDelay'] ?? 1);
        if ($elapsed < $min) {
            return $this->match('tooFast', ['elapsed' => $elapsed, 'min' => $min]);
        }
        return null;
    }
}
