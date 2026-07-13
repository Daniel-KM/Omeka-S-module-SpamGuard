<?php declare(strict_types=1);

namespace SpamGuard\Service;

use SpamGuard\SpamStrategy\SpamStrategyManager;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class SpamStrategyManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null)
    {
        $config = $container->get('Config');
        return new SpamStrategyManager($container, $config['spam_guard_strategies'] ?? []);
    }
}
