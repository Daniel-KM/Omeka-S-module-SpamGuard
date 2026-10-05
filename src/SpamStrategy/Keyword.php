<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;

class Keyword extends AbstractSpamStrategy
{
    /**
     * The keywords are managed in the configuration form of the module, so an
     * installation can adapt the list to its own collections: a legitimate term
     * of the domain would flag every message mentioning it.
     */
    public function check(SpamContext $context, array $settings): ?array
    {
        $haystack = trim(((string) $context->subject) . "\n" . ((string) $context->body));
        if ($haystack === '') {
            return null;
        }

        $keywords = array_map('trim', array_map('strval', (array) ($settings['keywords'] ?? [])));
        foreach (array_filter($keywords, fn ($v) => $v !== '') as $keyword) {
            if (preg_match('/\b' . preg_quote($keyword, '/') . '\b/ui', $haystack)) {
                return $this->match('keyword', $keyword);
            }
        }
        return null;
    }
}
