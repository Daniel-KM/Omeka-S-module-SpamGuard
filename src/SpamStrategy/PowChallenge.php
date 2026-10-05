<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

final class PowChallenge extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        // The calling module may not issue any challenge, for example when its
        // own option skips it, so a missing nonce must not be a spam then.
        if (!empty($context->extra['powSkip'])) {
            return null;
        }
        $difficulty = (int) ($settings['difficulty'] ?? 4);
        $salt = $context->extra['powSalt'] ?? null;
        $nonce = $context->extra['powNonce'] ?? null;
        if (!is_string($salt) || $salt === '' || !is_string($nonce) || $nonce === '') {
            return $this->match('powChallenge', 'missing');
        }
        // The client (ContactUs JS and the local checker) hashes the salt and
        // the nonce joined by a colon, so keep the same separator here.
        $prefix = str_repeat('0', $difficulty);
        $hash = hash('sha256', $salt . ':' . $nonce);
        if (!hash_equals($prefix, substr($hash, 0, $difficulty))) {
            return $this->match('powChallenge', 'invalid');
        }
        return null;
    }
}
