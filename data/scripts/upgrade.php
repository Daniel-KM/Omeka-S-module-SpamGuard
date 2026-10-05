<?php declare(strict_types=1);

namespace SpamGuard;

use Common\Stdlib\PsrMessage;

/**
 * @var Module $this
 * @var \Laminas\ServiceManager\ServiceLocatorInterface $services
 * @var string $newVersion
 * @var string $oldVersion
 *
 * @var \Laminas\Log\Logger $logger
 * @var \Omeka\Settings\Settings $settings
 * @var \Omeka\Mvc\Controller\Plugin\Messenger $messenger
 */
$plugins = $services->get('ControllerPluginManager');
$logger = $services->get('Omeka\Logger');
$settings = $services->get('Omeka\Settings');
$messenger = $plugins->get('messenger');

if (version_compare((string) $oldVersion, '3.4.1', '<')) {
    // The keywords were read from two files, one in this module and one in the
    // module Common. They are now a setting, editable in the configuration
    // form, that replaces them, so seed it from the files to keep the keywords
    // added manually.
    $keywords = (array) ($settings->get('spamguard_keywords') ?: []);

    $local = dirname(__DIR__) . '/params/spam_keywords.php';
    if (is_file($local)) {
        $keywords = array_merge($keywords, (array) include $local);
    }

    if (class_exists(\Common\Module::class)) {
        $commonFile = dirname((string) (new \ReflectionClass(\Common\Module::class))->getFileName())
            . '/data/mailer/spam_keywords.php';
        if (is_file($commonFile)) {
            $keywords = array_merge($keywords, (array) include $commonFile);
        }
    }

    $keywords = array_values(array_unique(array_filter(
        array_map('trim', array_map('strval', $keywords)),
        fn ($v) => $v !== ''
    )));
    sort($keywords, SORT_STRING);
    $settings->set('spamguard_keywords', $keywords);

    $message = new PsrMessage(
        'The spam keywords are now editable in the configuration form of the module. {count} keywords were imported from the files of the modules SpamGuard and Common, that are no longer read.', // @translate
        ['count' => count($keywords)]
    );
    $messenger->addSuccess($message);
    $logger->notice($message->getMessage(), $message->getContext());

    // New strategy: links to the top level domains abused by spammers.
    $config = require dirname(__DIR__, 2) . '/config/module.config.php';
    $settings->set('spamguard_link_tlds', $config['spamguard']['config']['spamguard_link_tlds']);
    $enabled = (array) ($settings->get('spamguard_enabled_strategies') ?: []);
    if ($enabled && !in_array('linkTld', $enabled, true)) {
        $enabled[] = 'linkTld';
        $settings->set('spamguard_enabled_strategies', $enabled);
    }
    $message = new PsrMessage(
        'A new strategy marks as spam the messages containing a link to a top level domain abused by spammers ({tlds}). The list can be adapted in the config form.', // @translate
        ['tlds' => implode(', ', $config['spamguard']['config']['spamguard_link_tlds'])]
    );
    $messenger->addSuccess($message);

    // Journal of the verdicts and reputation of the ip, for all modules.
    $connection = $services->get('Omeka\Connection');
    $connection->executeStatement(str_replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', (string) file_get_contents(dirname(__DIR__) . '/install/schema.sql')));
    $settings->set('spamguard_ip_reputation_hours', 24);
    $settings->set('spamguard_ip_trusted', []);
    $message = new PsrMessage(
        'A new strategy, disabled by default, marks as spam a message sent from an ip that sent a spam detected by a reliable check in any module during the last hours. Before enabling it, add the networks of your institution to the trusted ips in the config form, since its visitors may share a few public ips.' // @translate
    );
    $messenger->addSuccess($message);
}
