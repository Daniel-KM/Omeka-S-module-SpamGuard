<?php declare(strict_types=1);

namespace SpamGuard;

// Common may be installed but not registered in autoloader, in particular
// during upgrade. So dynamically register all classes of the module.
if (!defined('COMMON_PSR4_FALLBACK')) {
    foreach ([
        OMEKA_PATH . '/modules/Common/src',
        OMEKA_PATH . '/composer-addons/modules/Common/src',
        dirname(__DIR__) . '/Common/src',
    ] as $commonSrc) {
        if (file_exists($commonSrc . '/TraitModule.php')) {
            define('COMMON_PSR4_FALLBACK', $commonSrc);
            spl_autoload_register(static function ($class): void {
                if (str_starts_with($class, 'Common\\')) {
                    $file = COMMON_PSR4_FALLBACK . '/' . strtr(substr($class, 7), '\\', '/') . '.php';
                    if (file_exists($file)) {
                        require_once $file;
                    }
                }
            });
            break;
        }
    }
}

use Common\TraitModule;
use Omeka\Module\AbstractModule;

/**
 * Spam Guard
 */
class Module extends AbstractModule
{
    use TraitModule;

    const NAMESPACE = __NAMESPACE__;
}
