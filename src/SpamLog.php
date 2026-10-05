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
     * Statistics of the journal for the last days: the submissions, the spams,
     * the decisions of the admins and the spams by reason and by source.
     *
     * The reasons are stored as a list, so the aggregation is done here; the
     * journal is bounded by the retention, so the rows are few.
     *
     * @return array{days: int, total: int, spams: int, notSpamByAdmin: int, spamByAdmin: int, byReason: array<string, int>, bySource: array<string, array{total: int, spams: int}>}
     */
    public function statistics(int $days = self::RETENTION_DAYS): array
    {
        $stats = [
            'days' => $days,
            'total' => 0,
            'spams' => 0,
            'notSpamByAdmin' => 0,
            'spamByAdmin' => 0,
            'byReason' => [],
            'bySource' => [],
        ];
        $since = date('Y-m-d H:i:s', strtotime('-' . max(1, $days) . ' days'));
        $rows = $this->connection->executeQuery(
            'SELECT `source`, `reasons`, `is_spam` FROM `spam_log` WHERE `created` >= :since',
            ['since' => $since]
        )->iterateAssociative();
        foreach ($rows as $row) {
            $reasons = array_filter(explode(',', (string) $row['reasons']));
            $isAdmin = in_array('admin', $reasons, true);
            if ($isAdmin) {
                $row['is_spam'] ? ++$stats['spamByAdmin'] : ++$stats['notSpamByAdmin'];
                continue;
            }
            ++$stats['total'];
            $source = (string) $row['source'];
            $stats['bySource'][$source] ??= ['total' => 0, 'spams' => 0];
            ++$stats['bySource'][$source]['total'];
            if (!$row['is_spam']) {
                continue;
            }
            ++$stats['spams'];
            ++$stats['bySource'][$source]['spams'];
            foreach ($reasons as $reason) {
                $stats['byReason'][$reason] = ($stats['byReason'][$reason] ?? 0) + 1;
            }
        }
        arsort($stats['byReason']);
        ksort($stats['bySource']);
        return $stats;
    }

    /**
     * Number of submissions of the ip during the last minutes, spam or not.
     */
    public function countRecent(string $ip, int $minutes): int
    {
        if ($ip === '' || $minutes <= 0) {
            return 0;
        }
        $since = date('Y-m-d H:i:s', strtotime('-' . $minutes . ' minutes'));
        return (int) $this->connection->executeQuery(
            'SELECT COUNT(*) FROM `spam_log` WHERE `ip` = :ip AND `created` >= :since',
            ['ip' => $ip, 'since' => $since]
        )->fetchOne();
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
