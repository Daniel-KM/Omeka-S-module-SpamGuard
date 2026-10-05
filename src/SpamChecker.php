<?php declare(strict_types=1);

namespace SpamGuard;

use SpamGuard\SpamStrategy\SpamStrategyManager;

class SpamChecker
{
    public function __construct(
        private readonly SpamStrategyManager $strategies,
        private readonly array $enabled,
        private readonly array $settings,
        private readonly ?SpamLog $spamLog = null,
    ) {
    }

    public function check(SpamContext $context): SpamResult
    {
        $reasons = [];
        $details = [];
        foreach ($this->enabled as $name) {
            if (!$this->strategies->has($name)) {
                continue;
            }
            $strategy = $this->strategies->get($name);
            $out = $strategy->check($context, $this->settings[$name] ?? []);
            if ($out !== null && isset($out['reason'])) {
                $reasons[] = $out['reason'];
                $details[$out['reason']] = $out['detail'] ?? null;
            }
        }
        // Record the spams in the journal, so the reputation of the ip covers
        // all the modules. The calling module sets its name as source.
        if ($reasons && $this->spamLog) {
            $this->spamLog->record($context->ip, (string) ($context->extra['source'] ?? 'unknown'), $reasons, true);
        }
        return new SpamResult($reasons, $details);
    }
}
