<?php declare(strict_types=1);

namespace SpamGuard\Form;

use Common\Form\Element as CommonElement;
use Laminas\Form\Form;
use Omeka\Form\Element as OmekaElement;

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
                        'dnsMx' => 'Email DNS MX check', // @translate
                        'dnsbl' => 'Client IP DNSBL check', // @translate
                        'bannedIp' => 'Banned IPs', // @translate
                        'ipReputation' => 'Reputation of the ip (recent spams of any module, see the trusted ips below)', // @translate
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
            ->add([
                'name' => 'spamguard_keywords',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Spam keywords', // @translate
                    'info' => 'One per line. A message whose subject or body contains one of them, as a whole word, is a spam. This list replaces the one of the module Common, that is no longer read. Check that a keyword is not a legitimate word of your collections before adding it.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_keywords',
                    'rows' => 10,
                ],
            ])
            ->add([
                'name' => 'spamguard_dnsbl_zones',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'DNSBL zones', // @translate
                    'info' => 'One per line, like zen.spamhaus.org.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_dnsbl_zones',
                    'rows' => 5,
                ],
            ])
            ->add([
                'name' => 'spamguard_ip_reputation_hours',
                'type' => CommonElement\OptionalNumber::class,
                'options' => [
                    'label' => 'Hours during which an ip that sent a spam is blocked', // @translate
                    'info' => 'A message sent from an ip that sent a spam in any module during this number of hours is a spam too. Only the spams detected by reliable checks count (honeypot, keyword, link, dnsbl, banned ip, admin), not the ones based on timing. Keep it short: many visitors may share the same ip.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_ip_reputation_hours',
                    'min' => 0,
                    'step' => 1,
                ],
            ])
            ->add([
                'name' => 'spamguard_ip_trusted',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Trusted ips, never blocked by the reputation', // @translate
                    'info' => 'One ip or range (cidr) by line, for example the networks of the institution, whose visitors share a few public ips.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_ip_trusted',
                    'rows' => 4,
                    'placeholder' => '192.0.2.0/24',
                ],
            ])
            ->add([
                'name' => 'spamguard_banned_ips',
                'type' => OmekaElement\ArrayTextarea::class,
                'options' => [
                    'label' => 'Banned IPs', // @translate
                    'info' => 'One per line, CIDR accepted.', // @translate
                ],
                'attributes' => [
                    'id' => 'spamguard_banned_ips',
                    'rows' => 5,
                ],
            ])
        ;
    }
}
