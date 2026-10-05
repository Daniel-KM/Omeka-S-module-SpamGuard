<?php declare(strict_types=1);

namespace SpamGuard;

use Doctrine\DBAL\Connection;

/**
 * Journal of the verdicts of the modules that check spam.
 *
 * The strategies judge a message alone, without memory. The journal keeps the
 * spams of all modules, so the reputation of an ip covers them all: a bot that
 * spammed the contact form is recognized when it comments. The manual changes
 * of an admin are recorded too, so a false positive cancels the reputation.
 */
class SpamLog
{
    /**
     * Number of days the verdicts are kept.
     */
    const RETENTION_DAYS = 30;

    /**
     * @var \Doctrine\DBAL\Connection
     */
    protected $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @param string $source Name of the module or of the form, like "contactus".
     * @param string[] $reasons The reasons of the verdict, or ["admin"].
     */
    public function record(?string $ip, string $source, array $reasons, bool $isSpam): void
    {
        if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        $this->connection->insert('spam_log', [
            'ip' => $ip,
            'source' => mb_substr($source, 0, 190),
            'reasons' => $reasons ? mb_substr(implode(',', $reasons), 0, 190) : null,
            'is_spam' => (int) $isSpam,
            'created' => date('Y-m-d H:i:s'),
        ]);
        // Purge the old verdicts from time to time, the index keeps it quick.
        if (random_int(1, 100) === 1) {
            $this->connection->executeStatement(
                'DELETE FROM `spam_log` WHERE `created` < :before',
                ['before' => date('Y-m-d H:i:s', strtotime('-' . self::RETENTION_DAYS . ' days'))]
            );
        }
    }

    /**
     * Has the ip sent a spam detected by one of the given reasons recently?
     *
     * A later decision of an admin that a message of this ip is not a spam
     * cancels the previous spams, so a false positive does not block the ip.
     *
     * @param string[] $reasons Only the spams with one of these reasons count.
     */
    public function hasRecentSpam(string $ip, int $hours, array $reasons): bool
    {
        if ($ip === '' || $hours <= 0 || !$reasons) {
            return false;
        }
        $since = date('Y-m-d H:i:s', strtotime('-' . $hours . ' hours'));
        $rows = $this->connection->executeQuery(
            'SELECT `reasons`, `is_spam`, `created` FROM `spam_log` WHERE `ip` = :ip AND `created` >= :since ORDER BY `created` DESC, `id` DESC',
            ['ip' => $ip, 'since' => $since]
        )->fetchAllAssociative();
        foreach ($rows as $row) {
            $rowReasons = explode(',', (string) $row['reasons']);
            // The most recent decision of an admin prevails.
            if (!$row['is_spam'] && in_array('admin', $rowReasons, true)) {
                return false;
            }
            if ($row['is_spam'] && array_intersect($rowReasons, $reasons)) {
                return true;
            }
        }
        return false;
    }
}
