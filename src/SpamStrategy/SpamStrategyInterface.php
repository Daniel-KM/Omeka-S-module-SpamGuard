<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

interface SpamStrategyInterface
{
    /**
     * @return array|null Null si OK, sinon ['reason' => string, 'detail' => mixed].
     */
    public function check(SpamContext $context, array $settings): ?array;
}
