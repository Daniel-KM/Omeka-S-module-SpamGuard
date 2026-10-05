<?php declare(strict_types=1);

namespace SpamGuard\Service;

use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;
use SpamGuard\Stdlib\FormToken;

class FormTokenFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $services, $requestedName, ?array $options = null)
    {
        return new FormToken(FormToken::secret($services->get('Omeka\Settings')));
    }
}
