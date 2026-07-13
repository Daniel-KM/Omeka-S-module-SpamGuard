<?php declare(strict_types=1);

namespace SpamGuard;

use Laminas\Mvc\Controller\AbstractController;
use Laminas\View\Renderer\PhpRenderer;
use Omeka\Module\AbstractModule;

class Module extends AbstractModule
{
    public function getConfig()
    {
        return include __DIR__ . '/config/module.config.php';
    }

    public function install($serviceLocator)
    {
        $settings = $serviceLocator->get('Omeka\Settings');

        $configLocal = include __DIR__ . '/config/module.config.php';
        $configLocal = $configLocal['spamguard']['config'];

        foreach ($configLocal as $key => $value) {
            $settings->set($key, $value);
        }
    }

    public function uninstall($serviceLocator)
    {
        $settings = $serviceLocator->get('Omeka\Settings');

        $configLocal = include __DIR__ . '/config/module.config.php';
        $configLocal = $configLocal['spamguard']['config'];

        foreach (array_keys($configLocal) as $key) {
            $settings->delete($key);
        }
    }

    public function getConfigForm(PhpRenderer $renderer)
    {
        $formElementManager = $this->getServiceLocator()->get('FormElementManager');
        $settings = $this->getServiceLocator()->get('Omeka\Settings');

        $configLocal = include __DIR__ . '/config/module.config.php';
        $configLocal = $configLocal['spamguard']['config'];

        $values = [];
        foreach ($configLocal as $key => $value) {
            $values[$key] = $settings->get($key, $value);
        }

        $form = $formElementManager->get(Form\ConfigForm::class);
        $form->setData($values);

        return $renderer->formCollection($form, false);
    }

    public function handleConfigForm(AbstractController $controller)
    {
        $formElementManager = $this->getServiceLocator()->get('FormElementManager');
        $settings = $this->getServiceLocator()->get('Omeka\Settings');

        $form = $formElementManager->get(Form\ConfigForm::class);
        $form->setData($controller->params()->fromPost());
        if (!$form->isValid()) {
            $controller->messenger()->addErrors($form->getMessages());
            return false;
        }

        $formData = $form->getData();

        $settings->set('spamguard_enabled_strategies', $formData['spamguard_enabled_strategies'] ?? []);
        $settings->set('spamguard_min_delay', (int) ($formData['spamguard_min_delay'] ?? 1));

        return true;
    }
}
