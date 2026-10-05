<?php declare(strict_types=1);

namespace SpamGuardTest\SpamStrategy;

use SpamGuard\SpamContext;
use SpamGuard\SpamStrategy\LinkTld;
use PHPUnit\Framework\TestCase;

class LinkTldTest extends TestCase
{
    protected function settings(): array
    {
        return ['tlds' => ['top', 'buzz', 'xyz']];
    }

    public function testLinkToAbusedTldIsFlagged(): void
    {
        $r = (new LinkTld())->check(
            new SpamContext(body: 'Вам перевод 124469 руб. забрать тут https://kunirtyrt.top/JekpeKioO#ve13fS'),
            $this->settings()
        );
        $this->assertIsArray($r);
        $this->assertSame('linkTld', $r['reason']);
        $this->assertSame(['host' => 'kunirtyrt.top', 'tld' => 'top'], $r['detail']);
    }

    public function testLinkToLegitimateDomainPasses(): void
    {
        $this->assertNull((new LinkTld())->check(
            new SpamContext(body: 'Voir https://dante.univ-tlse2.fr/s/fr/item/12 et https://www.bnf.fr/fr'),
            $this->settings()
        ));
    }

    /**
     * The tld is the last label of the host, not a part of the path or of a
     * longer label.
     */
    public function testOnlyTheLastLabelOfTheHostIsChecked(): void
    {
        $s = new LinkTld();
        $this->assertNull($s->check(new SpamContext(body: 'https://example.org/top/page.xyz'), $this->settings()));
        $this->assertNull($s->check(new SpamContext(body: 'https://desktop.example.com/'), $this->settings()));
        $this->assertNull($s->check(new SpamContext(body: 'https://top.example.com/'), $this->settings()));
        $this->assertIsArray($s->check(new SpamContext(body: 'https://sub.sekalubanik.buzz/x'), $this->settings()));
    }

    public function testHostWithPortCredentialsOrUppercaseIsFlagged(): void
    {
        $s = new LinkTld();
        $this->assertIsArray($s->check(new SpamContext(body: 'https://bad.top:8080/x'), $this->settings()));
        $this->assertIsArray($s->check(new SpamContext(body: 'https://user:pass@bad.top/x'), $this->settings()));
        $this->assertIsArray($s->check(new SpamContext(body: 'HTTPS://BAD.TOP/X'), $this->settings()));
        $this->assertIsArray($s->check(new SpamContext(body: 'go to www.bad.top now'), $this->settings()));
    }

    /**
     * A domain mentioned without link, in a sentence, is not a link.
     */
    public function testDomainWithoutLinkPasses(): void
    {
        $this->assertNull((new LinkTld())->check(
            new SpamContext(body: 'Le site kunirtyrt.top est une arnaque.'),
            $this->settings()
        ));
    }

    public function testLinkInSubjectOrEncodedBodyIsFlagged(): void
    {
        $s = new LinkTld();
        $this->assertIsArray($s->check(new SpamContext(subject: 'https://bad.xyz', body: 'Hello'), $this->settings()));
        $this->assertIsArray($s->check(new SpamContext(body: '<a href=&quot;https://bad.top/x&quot;>x</a>'), $this->settings()));
    }

    public function testSettingsAreNormalized(): void
    {
        $s = new LinkTld();
        $this->assertIsArray($s->check(new SpamContext(body: 'https://bad.top/x'), ['tlds' => [' .TOP ', '']]));
        $this->assertNull($s->check(new SpamContext(body: 'https://bad.top/x'), ['tlds' => []]));
        $this->assertNull($s->check(new SpamContext(body: 'https://bad.top/x'), []));
    }

    /**
     * Messages of a real wave of spams, whose domain changed every few minutes
     * while the top level domain stayed the same.
     */
    public function testRotatingDomainsAreCaught(): void
    {
        $s = new LinkTld();
        foreach ([
            'Вам перевод 124469 руб. забрать тут https://kunirtyrt.top/JekpeKioO#ve13fS',
            'Вам перевод 101408 руб. забрать тут https://anarthyt.top/JaBcDeFg#x1',
            'Вам перевод 115550 руб. получить тут https://sekalubanik.buzz/JpoIjXbFp#nwdpc9',
        ] as $body) {
            $this->assertIsArray($s->check(new SpamContext(body: $body), $this->settings()), $body);
        }
    }
}
