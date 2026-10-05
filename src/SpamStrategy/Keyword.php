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

        // Decode the entities and remove the tags before the check. A body
        // stored as html writes "spécialisée" as "sp&eacute;cialis&eacute;e",
        // where "cialis" is surrounded by the non word characters of the
        // entities, so it would match as a whole word. It also defeats the
        // usual evasions, like "v&#105;agra" or "<b>via</b>gra".
        $haystack = $this->normalize(strip_tags(html_entity_decode($haystack, ENT_QUOTES | ENT_HTML5, 'UTF-8')));
        if (trim($haystack) === '') {
            return null;
        }

        $keywords = array_map('trim', array_map('strval', (array) ($settings['keywords'] ?? [])));
        foreach (array_filter($keywords, fn ($v) => $v !== '') as $keyword) {
            $pattern = $this->pattern($this->normalize($keyword));
            if ($pattern !== null && preg_match($pattern, $haystack)) {
                return $this->match('keyword', $keyword);
            }
        }
        return null;
    }

    /**
     * Defeat the usual evasions: the accents and the look-alike letters are
     * folded and the invisible characters are removed, so "vïagra" or a word
     * split by a zero width space matches "viagra".
     */
    protected function normalize(string $text): string
    {
        $text = mb_strtolower($text, 'UTF-8');
        // Zero width characters and soft hyphen.
        $text = (string) preg_replace('~[\x{200B}-\x{200D}\x{2060}\x{FEFF}\x{00AD}]~u', '', $text);
        if (class_exists('Normalizer')) {
            $text = (string) \Normalizer::normalize($text, \Normalizer::FORM_D);
            $text = (string) preg_replace('~\p{Mn}~u', '', $text);
        }
        // Cyrillic and greek look-alikes of latin letters.
        return strtr($text, [
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x', 'у' => 'y', 'і' => 'i', 'ѕ' => 's',
            'ο' => 'o', 'α' => 'a', 'ε' => 'e', 'ι' => 'i', 'ν' => 'v', 'ρ' => 'p', 'τ' => 't',
        ]);
    }

    /**
     * Pattern of a keyword as a whole word.
     *
     * A keyword that is a domain is matched as is. A plain word of five letters
     * or more tolerates a space or a dot between its letters ("v i a g r a",
     * "v.i.a.g.r.a"), a common evasion; a shorter one is matched as is, since
     * its letters would be found in any sentence.
     */
    protected function pattern(string $keyword): ?string
    {
        if ($keyword === '') {
            return null;
        }
        $isWord = (bool) preg_match('~^\p{L}+$~u', $keyword);
        $letters = $isWord && mb_strlen($keyword) >= 5
            ? implode('[\s.]{0,2}', array_map(fn ($c) => preg_quote($c, '/'), preg_split('~~u', $keyword, -1, PREG_SPLIT_NO_EMPTY)))
            : preg_quote($keyword, '/');
        return '/(?<![\p{L}\p{N}])' . $letters . '(?![\p{L}\p{N}])/ui';
    }
}
