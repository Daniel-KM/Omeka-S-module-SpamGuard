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
        ],
    ],
];
