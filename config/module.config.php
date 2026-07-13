<?php declare(strict_types=1);

namespace SpamGuard;

return [
    'service_manager' => [
        'factories' => [
            'SpamGuard\SpamChecker' => Service\SpamCheckerFactory::class,
            'SpamGuard\SpamStrategyManager' => Service\SpamStrategyManagerFactory::class,
        ],
    ],
    'spam_guard_strategies' => [
        'invokables' => [
            'honeypot' => SpamStrategy\Honeypot::class,
            'urlCount' => SpamStrategy\UrlCount::class,
            'keyword' => SpamStrategy\Keyword::class,
            'tooFast' => SpamStrategy\TooFast::class,
            'rateLimit' => SpamStrategy\RateLimit::class,
            'powChallenge' => SpamStrategy\PowChallenge::class,
            'dnsMx' => SpamStrategy\DnsMx::class,
            'dnsbl' => SpamStrategy\Dnsbl::class,
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
            ],
            'spamguard_min_delay' => 1,
            'spamguard_max_urls' => 3,
            'spamguard_rate_limit_seconds' => 10,
            'spamguard_pow_difficulty' => 4,
            'spamguard_dnsbl_zones' => [
                'zen.spamhaus.org',
            ],
        ],
    ],
];
