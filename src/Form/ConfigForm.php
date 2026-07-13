<?php declare(strict_types=1);

namespace SpamGuard\Form;

use Common\Form\Element as CommonElement;
use Laminas\Form\Element;
use Laminas\Form\Form;

class ConfigForm extends Form
{
    public function init()
    {
        $this
            ->add([
                'name' => 'spamguard_enabled_strategies',
                'type' => CommonElement\OptionalMultiCheckbox::class,
                'options' => [
                    'label' => 'Enabled spam strategies', // @translate
                    'value_options' => [
                        'honeypot' => 'Honeypot (trap field)', // @translate
                        'urlCount' => 'Excessive URL count', // @translate
                        'keyword' => 'Forbidden keywords', // @translate
                        'tooFast' => 'Too fast submission', // @translate
                    ],
                ],
                'attributes' => [
                    'id' => 'spamguard_enabled_strategies',
                ],
            ])
            ->add([
                'name' => 'spamguard_min_delay',
                'type' => CommonElement\OptionalNumber::class,
                'options' => [
                    'label' => 'Minimum submission delay (seconds)', // @translate
                    'info' => 'Minimum delay between form load and submission.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_min_delay',
                    'min' => 0,
                    'value' => 1,
                ],
            ])
            ->add([
                'name' => 'spamguard_max_urls',
                'type' => CommonElement\OptionalNumber::class,
                'options' => [
                    'label' => 'Maximum URL count', // @translate
                    'info' => 'Above this threshold, the submission is considered spam.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_max_urls',
                    'min' => 0,
                    'value' => 3,
                ],
            ])
        ;
    }
}
