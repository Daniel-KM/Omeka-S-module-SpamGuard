<?php declare(strict_types=1);

namespace SpamGuard\SpamStrategy;

use Laminas\ServiceManager\AbstractPluginManager;
use Laminas\ServiceManager\Exception\InvalidServiceException;

class SpamStrategyManager extends AbstractPluginManager
{
    protected $instanceOf = SpamStrategyInterface::class;

    public function validate($instance)
    {
        if (!$instance instanceof SpamStrategyInterface) {
            throw new InvalidServiceException(sprintf(
                'Plugin of type "%s" is invalid; must implement %s.',
                is_object($instance) ? get_class($instance) : gettype($instance),
                SpamStrategyInterface::class
            ));
        }
    }
}
