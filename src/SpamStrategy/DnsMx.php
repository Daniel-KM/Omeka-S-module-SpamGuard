<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class DnsMx extends AbstractSpamStrategy
{
    /** @var callable */
    private $resolver;

    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver ?? static fn (string $domain): bool => checkdnsrr($domain, 'MX');
    }

    public function check(SpamContext $context, array $settings): ?array
    {
        $email = (string) ($context->email ?? '');
        if ($email === '' || !str_contains($email, '@')) {
            return null;
        }
        $parts = explode('@', $email);
        $domain = end($parts);
        if ($domain === '' || $domain === false) {
            return null;
        }
        if (!($this->resolver)($domain)) {
            return $this->match('dnsMx', ['domain' => $domain]);
        }
        return null;
    }
}
