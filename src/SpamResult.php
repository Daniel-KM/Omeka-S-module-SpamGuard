<?php declare(strict_types=1);

namespace SpamGuard;

final class SpamResult
{
    public function __construct(
        public readonly array $reasons,
        public readonly array $details = [],
    ) {
    }

    public function isSpam(): bool
    {
        return $this->reasons !== [];
    }

    public function reasonList(): string
    {
        return implode(',', $this->reasons);
    }
}
