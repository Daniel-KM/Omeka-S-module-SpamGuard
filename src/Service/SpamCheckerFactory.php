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
            'tooFast' => ['minDelay' => (int) ($settings->get('spamguard_min_delay') ?? 1)],
            'urlCount' => ['maxUrls' => (int) ($settings->get('spamguard_max_urls') ?? 3)],
            'bannedIp' => ['bannedIps' => (array) ($settings->get('spamguard_banned_ips') ?? [])],
            'powChallenge' => ['difficulty' => (int) ($settings->get('spamguard_pow_difficulty') ?? 4)],
            'rateLimit' => ['minInterval' => (int) ($settings->get('spamguard_rate_limit_seconds') ?? 10)],
            'dnsbl' => ['zones' => (array) ($settings->get('spamguard_dnsbl_zones') ?? [])],
            'keyword' => ['keywords' => (array) ($settings->get('spamguard_keywords') ?? [])],
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
