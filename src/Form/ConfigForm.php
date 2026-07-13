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
                        'rateLimit' => 'Rate limit per IP/session', // @translate
                        'powChallenge' => 'Proof-of-Work challenge (hashcash)', // @translate
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
            ->add([
                'name' => 'spamguard_rate_limit_seconds',
                'type' => CommonElement\OptionalNumber::class,
                'options' => [
                    'label' => 'Rate-limit interval (seconds)', // @translate
                    'info' => 'Minimum delay between two submissions from the same IP or session.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_rate_limit_seconds',
                    'min' => 0,
                    'value' => 10,
                ],
            ])
            ->add([
                'name' => 'spamguard_pow_difficulty',
                'type' => CommonElement\OptionalNumber::class,
                'options' => [
                    'label' => 'Proof-of-Work difficulty (number of leading hex zeros)', // @translate
                    'info' => 'Number of leading hex zeros required on the hash (sha256). The higher the value, the more expensive the client-side computation.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_pow_difficulty',
                    'min' => 0,
                    'value' => 4,
                ],
            ])
        ;
    }
}
