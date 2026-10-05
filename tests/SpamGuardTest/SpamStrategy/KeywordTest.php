<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\Keyword;
use PHPUnit\Framework\TestCase;

class KeywordTest extends TestCase
{
    /**
     * The keywords come from the settings, filled by the configuration form.
     */
    protected function settings(array $keywords = ['crypto-pump']): array
    {
        return ['keywords' => $keywords];
    }

    public function testCleanBodyPasses(): void
    {
        $s = new Keyword();
        $this->assertNull($s->check(
            new SpamContext(body: 'Bonjour, ceci est un message légitime.'),
            $this->settings()
        ));
    }

    public function testBodyWithKeywordFlags(): void
    {
        $s = new Keyword();
        $r = $s->check(new SpamContext(body: 'Join our crypto-pump group now!'), $this->settings());
        $this->assertIsArray($r);
        $this->assertSame('keyword', $r['reason']);
        $this->assertSame('crypto-pump', $r['detail']);
    }

    public function testSubjectWithKeywordFlags(): void
    {
        $s = new Keyword();
        $r = $s->check(
            new SpamContext(subject: 'Amazing crypto-pump offer', body: 'Hello'),
            $this->settings()
        );
        $this->assertIsArray($r);
        $this->assertSame('keyword', $r['reason']);
    }

    /**
     * The list of the settings is the whole list: without any keyword, the
     * strategy cannot flag anything.
     */
    public function testWithoutKeywordNothingIsFlagged(): void
    {
        $s = new Keyword();
        $this->assertNull($s->check(new SpamContext(body: 'Join our crypto-pump group!'), []));
        $this->assertNull($s->check(new SpamContext(body: 'Buy viagra now'), $this->settings([])));
    }

    public function testCheckIsCaseInsensitive(): void
    {
        $s = new Keyword();
        $r = $s->check(new SpamContext(body: 'Join our CRYPTO-PUMP group'), $this->settings());
        $this->assertIsArray($r);
        $this->assertSame('crypto-pump', $r['detail']);
    }

    /**
     * The keyword is checked as a whole word, so a legitimate word containing
     * it is not a spam.
     */
    public function testKeywordIsCheckedOnWordBoundaries(): void
    {
        $s = new Keyword();
        $this->assertNull($s->check(
            new SpamContext(body: 'This poster is about a postal service.'),
            $this->settings(['post'])
        ));
        $this->assertIsArray($s->check(
            new SpamContext(body: 'Read this post now.'),
            $this->settings(['post'])
        ));
    }

    /**
     * The textarea of the configuration form may leave spaces and empty lines.
     */
    public function testEmptyAndPaddedKeywordsAreIgnored(): void
    {
        $s = new Keyword();
        $r = $s->check(
            new SpamContext(body: 'Join our zzz-own-keyword group'),
            $this->settings(['', '   ', '  zzz-own-keyword  '])
        );
        $this->assertIsArray($r);
        $this->assertSame('zzz-own-keyword', $r['detail']);
    }

    /**
     * A legitimate word containing a keyword must not be a spam, even when the
     * body is stored as html: "spécialisée" is written "sp&eacute;cialis&eacute;e",
     * where "cialis" is surrounded by non word characters.
     */
    public function testKeywordInsideAnEncodedWordIsNotASpam(): void
    {
        $s = new Keyword();
        $settings = $this->settings(['cialis']);

        $this->assertNull($s->check(new SpamContext(body: 'Une usine spécialisée dans la laine.'), $settings));
        $this->assertNull($s->check(new SpamContext(body: 'Une usine sp&eacute;cialis&eacute;e dans la laine.'), $settings));
        $this->assertNull($s->check(new SpamContext(body: '<p>Une usine sp&eacute;cialis&eacute;e.</p>'), $settings));
        $this->assertNull($s->check(new SpamContext(body: 'Un specialiste du textile.'), $settings));

        $r = $s->check(new SpamContext(body: 'Buy cialis now'), $settings);
        $this->assertIsArray($r);
        $this->assertSame('cialis', $r['detail']);
    }

    /**
     * Decoding the entities and removing the tags also defeats the usual
     * evasions of a spammer.
     */
    public function testEncodedAndSplitKeywordIsStillFlagged(): void
    {
        $s = new Keyword();
        $settings = $this->settings(['viagra']);

        foreach (['v&#105;agra', '<b>via</b>gra', 'vi<!-- x -->agra'] as $body) {
            $r = $s->check(new SpamContext(body: 'Buy ' . $body . ' now'), $settings);
            $this->assertIsArray($r, sprintf('The body "%s" is not flagged.', $body));
            $this->assertSame('viagra', $r['detail']);
        }
    }

    public function testEmptyContextPasses(): void
    {
        $s = new Keyword();
        $this->assertNull($s->check(new SpamContext(), $this->settings()));
    }
}
