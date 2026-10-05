<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

/**
 * Flag a message containing a link to a top level domain abused by spammers.
 *
 * The bots rotate their domains every few hours, so listing them as keywords
 * is always late, but they stay on a few cheap top level domains (top, buzz,
 * xyz, etc.), rarely used by the legitimate correspondents of an institution.
 */
class LinkTld extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        $tlds = array_filter(array_map(
            fn ($v) => strtolower(trim((string) $v, " \t\n\r\0\x0B.")),
            (array) ($settings['tlds'] ?? [])
        ), 'strlen');
        if (!$tlds) {
            return null;
        }

        $haystack = ((string) $context->subject) . "\n" . ((string) $context->body);
        $haystack = html_entity_decode($haystack, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if (!preg_match_all('~(?:\bhttps?://|\bwww\.)([^\s/?#<>"\']+)~i', $haystack, $matches)) {
            return null;
        }

        foreach ($matches[1] as $host) {
            // Remove the credentials, the port and the final dot of the host.
            $host = strtolower(rtrim((string) preg_replace('~^.*@|:\d+$~', '', $host), '.'));
            $tld = substr((string) strrchr($host, '.'), 1);
            if ($tld !== '' && in_array($tld, $tlds, true)) {
                return $this->match('linkTld', ['host' => $host, 'tld' => $tld]);
            }
        }
        return null;
    }
}
