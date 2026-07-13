<?php declare(strict_types=1);

namespace SpamGuard;

final class SpamContext
{
    public function __construct(
        public readonly ?string $ip = null,
        public readonly ?string $userAgent = null,
        public readonly ?string $email = null,
        public readonly ?string $subject = null,
        public readonly ?string $body = null,
        public readonly ?int $formLoadedAt = null,
        public readonly ?string $honeypotValue = null,
        public readonly ?int $userId = null,
        public readonly array $extra = [],
    ) {
    }
}
