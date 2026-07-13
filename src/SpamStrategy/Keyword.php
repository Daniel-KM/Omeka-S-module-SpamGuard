<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use SpamGuard\SpamContext;
use ReflectionClass;

class Keyword extends AbstractSpamStrategy
{
    private static ?array $cache = null;

    public function check(SpamContext $context, array $settings): ?array
    {
        $haystack = trim(((string) $context->subject) . "\n" . ((string) $context->body));
        if ($haystack === '') {
            return null;
        }
        foreach ($this->keywords() as $kw) {
            if (preg_match('/\b' . preg_quote($kw, '/') . '\b/ui', $haystack)) {
                return $this->match('keyword', $kw);
            }
        }
        return null;
    }

    private function keywords(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }

        $keywords = [];

        $local = dirname(__DIR__, 2) . '/data/params/spam_keywords.php';
        if (is_file($local)) {
            $keywords = array_merge($keywords, (array) include $local);
        }

        if (class_exists(\Common\Module::class, false)) {
            $ref = new ReflectionClass(\Common\Module::class);
            $commonFile = dirname((string) $ref->getFileName()) . '/data/mailer/spam_keywords.php';
            if (is_file($commonFile)) {
                $keywords = array_merge($keywords, (array) include $commonFile);
            }
        }

        $keywords = array_filter(array_map('strval', $keywords), fn ($v) => $v !== '');
        self::$cache = array_values(array_unique($keywords));
        return self::$cache;
    }
}
