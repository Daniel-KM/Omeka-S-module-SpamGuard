<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class Honeypot extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        $value = $context->honeypotValue;
        if ($value === null || $value === '') {
            return null;
        }
        return $this->match('honeypot', $value);
    }
}
