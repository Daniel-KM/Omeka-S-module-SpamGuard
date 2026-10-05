<?php declare(strict_types=1);

namespace SpamGuard\Stdlib;

use Omeka\Settings\Settings;

/**
 * Signed token sent with a public form, so the checks do not depend on the
 * session.
 *
 * A module stores the time of display of its form and the salt of its
 * proof-of-work in a single key of the session, so a visitor who opens the form
 * in a second tab, or a page with two forms, receives a new salt, and the
 * message of the first form fails the proof-of-work. The token carries them in
 * a hidden field of each form, signed with a secret of the installation and
 * bound to the ip of the visitor, so it cannot be forged nor reused from
 * another ip.
 */
class FormToken
{
    /**
     * Maximum age of a token: a visitor may take hours to write a message.
     */
    const MAX_AGE = 86400;

    /**
     * @var string
     */
    protected $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * Get the secret of the installation, created on first use.
     */
    public static function secret(Settings $settings): string
    {
        $secret = (string) $settings->get('spamguard_token_secret');
        if ($secret === '') {
            $secret = bin2hex(random_bytes(32));
            $settings->set('spamguard_token_secret', $secret);
        }
        return $secret;
    }

    public function issue(string $salt, string $ip, ?int $now = null): string
    {
        $issuedAt = (string) ($now ?? time());
        return $issuedAt . '.' . $salt . '.' . $this->sign($issuedAt, $salt, $ip);
    }

    /**
     * Check a token and return its time of issue and its salt.
     *
     * @return array{issuedAt: int, salt: string}|null Null when the token is
     * missing, forged, issued for another ip, too old or in the future.
     */
    public function read(?string $token, string $ip, ?int $now = null): ?array
    {
        $parts = explode('.', (string) $token);
        if (count($parts) !== 3 || !ctype_digit($parts[0]) || !ctype_xdigit($parts[1] ?: '0')) {
            return null;
        }
        [$issuedAt, $salt, $signature] = $parts;
        if (!hash_equals($this->sign($issuedAt, $salt, $ip), $signature)) {
            return null;
        }
        $age = ($now ?? time()) - (int) $issuedAt;
        if ($age < 0 || $age > self::MAX_AGE) {
            return null;
        }
        return ['issuedAt' => (int) $issuedAt, 'salt' => $salt];
    }

    protected function sign(string $issuedAt, string $salt, string $ip): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', $issuedAt . '|' . $salt . '|' . $ip, $this->secret, true)), '+/', '-_'), '=');
    }
}
