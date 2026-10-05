<?php declare(strict_types=1);

namespace SpamGuard\Service;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SpamGuard\SpamStrategy\IpReputation;

class IpReputationFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new IpReputation($services->get('SpamGuard\SpamLog'));
    }
}
