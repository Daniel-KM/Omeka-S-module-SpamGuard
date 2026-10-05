<?php declare(strict_types=1);

namespace SpamGuard;

return [
    'service_manager' => [
        'factories' => [
            'SpamGuard\FormToken' => Service\FormTokenFactory::class,
            'SpamGuard\SpamChecker' => Service\SpamCheckerFactory::class,
            'SpamGuard\SpamLog' => Service\SpamLogFactory::class,
            'SpamGuard\SpamStrategyManager' => Service\SpamStrategyManagerFactory::class,
        ],
    ],
    'spam_guard_strategies' => [
        'factories' => [
            'ipReputation' => Service\IpReputationFactory::class,
        ],
        'invokables' => [
            'honeypot' => SpamStrategy\Honeypot::class,
            'urlCount' => SpamStrategy\UrlCount::class,
            'keyword' => SpamStrategy\Keyword::class,
            'tooFast' => SpamStrategy\TooFast::class,
            'rateLimit' => SpamStrategy\RateLimit::class,
            'powChallenge' => SpamStrategy\PowChallenge::class,
            'dnsMx' => SpamStrategy\DnsMx::class,
            'dnsbl' => SpamStrategy\Dnsbl::class,
            'bannedIp' => SpamStrategy\BannedIp::class,
            'linkTld' => SpamStrategy\LinkTld::class,
        ],
    ],
    'form_elements' => [
        'invokables' => [
            Form\ConfigForm::class => Form\ConfigForm::class,
        ],
    ],
    'translator' => [
        'translation_file_patterns' => [
            [
                'type' => 'gettext',
                'base_dir' => dirname(__DIR__) . '/language',
                'pattern' => '%s.mo',
                'text_domain' => null,
            ],
        ],
    ],
    'spamguard' => [
        'config' => [
            'spamguard_enabled_strategies' => [
                'honeypot',
                'urlCount',
                'keyword',
                'tooFast',
                'rateLimit',
                'powChallenge',
                'dnsMx',
                'dnsbl',
                'bannedIp',
                'linkTld',
            ],
            'spamguard_min_delay' => 2,
            'spamguard_max_urls' => 3,
            'spamguard_rate_limit_seconds' => 10,
            'spamguard_pow_difficulty' => 4,
            // The whole list of keywords, editable in the configuration form.
            // It is seeded from the list of the module Common, that is no
            // longer read once the module is installed: the list below replaces
            // it.
            'spamguard_keywords' => [
                'adf.ly',
                'anarthyt.top',
                'b.link',
                'bit.do',
                'bit.ly',
                'bitly.com',
                'bl.ink',
                'cialis',
                'clck.ru',
                'crypto-pump',
                'cutt.ly',
                'goo.gl',
                'goo.su',
                'is.gd',
                'kunirtyrt.top',
                'levitra',
                'mcaf.ee',
                'ow.ly',
                'po.st',
                'qr.ae',
                'rb.gy',
                'rebrand.ly',
                's.id',
                'sekalubanik.buzz',
                'shor.by',
                'short.io',
                'shorte.st',
                'shorturl.at',
                't.ly',
                't2m.io',
                'tiny.cc',
                'tinycc',
                'tinyurl',
                'tinyurl.com',
                'tny.im',
                'tr.im',
                'urlz.fr',
                'urlzs.com',
                'v.gd',
                'viagra',
                'x.co',
                'zpr.io',
            ],
            // Top level domains abused by spammers. A link to one of them marks
            // the message as spam.
            'spamguard_link_tlds' => [
                'bond',
                'buzz',
                'cfd',
                'click',
                'cyou',
                'icu',
                'monster',
                'quest',
                'rest',
                'sbs',
                'top',
                'xyz',
            ],
            'spamguard_dnsbl_zones' => [
                'sbl-xbl.spamhaus.org',
            ],
            'spamguard_banned_ips' => [],
            'spamguard_ip_reputation_hours' => 24,
            'spamguard_ip_trusted' => [],
        ],
    ],
];
