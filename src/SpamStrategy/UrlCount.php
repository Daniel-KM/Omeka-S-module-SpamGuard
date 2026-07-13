<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class UrlCount extends AbstractSpamStrategy
{
    public function check(SpamContext $context, array $settings): ?array
    {
        $haystack = ((string) $context->subject) . "\n" . ((string) $context->body);
        $max = (int) ($settings['maxUrls'] ?? 3);
        $count = preg_match_all('~\bhttps?://\S+~i', $haystack);
        if ($count > $max) {
            return $this->match('urlCount', ['count' => $count]);
        }
        return null;
    }
}
