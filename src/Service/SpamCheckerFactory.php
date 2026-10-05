<?php declare(strict_types=1);

namespace SpamGuard\Service;

use SpamGuard\SpamChecker;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class SpamCheckerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        $settings = $services->get('Omeka\Settings');
        $enabled = $settings->get('spamguard_enabled_strategies') ?: [
            'honeypot', 'tooFast', 'keyword', 'urlCount', 'dnsMx', 'bannedIp', 'powChallenge',
        ];
        $stratSettings = [
            'urlCount' => ['maxUrls' => (int) ($settings->get('spamguard_max_urls') ?? 3)],
            'keyword' => ['keywords' => (array) ($settings->get('spamguard_keywords') ?? [])],
            'tooFast' => ['minDelay' => (int) ($settings->get('spamguard_min_delay') ?? 1)],
            'rateLimit' => ['minInterval' => (int) ($settings->get('spamguard_rate_limit_seconds') ?? 10)],
            'powChallenge' => ['difficulty' => (int) ($settings->get('spamguard_pow_difficulty') ?? 4)],
            'dnsbl' => ['zones' => (array) ($settings->get('spamguard_dnsbl_zones') ?? [])],
            'linkTld' => ['tlds' => (array) ($settings->get('spamguard_link_tlds') ?? [])],
            'bannedIp' => ['bannedIps' => (array) ($settings->get('spamguard_banned_ips') ?? [])],
            'ipReputation' => [
                'hours' => (int) ($settings->get('spamguard_ip_reputation_hours') ?? 24),
                'trusted' => (array) ($settings->get('spamguard_ip_trusted') ?? []),
            ],
        ];
        return new SpamChecker(
            $services->get('SpamGuard\SpamStrategyManager'),
            (array) $enabled,
            $stratSettings,
            $services->get('SpamGuard\SpamLog'),
        );
    }
}
