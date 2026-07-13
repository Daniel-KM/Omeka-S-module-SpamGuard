<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

abstract class AbstractSpamStrategy implements SpamStrategyInterface
{
    protected function match(string $reason, $detail = null): array
    {
        return ['reason' => $reason, 'detail' => $detail];
    }
}
