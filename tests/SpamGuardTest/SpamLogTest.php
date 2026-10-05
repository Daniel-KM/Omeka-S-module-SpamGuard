<?php declare(strict_types=1);

namespace SpamGuardTest;

use Omeka\Test\AbstractHttpControllerTestCase;
use SpamGuard\SpamLog;

/**
 * Tests the journal of the verdicts against the database.
 *
 * @group integration
 */
class SpamLogTest extends AbstractHttpControllerTestCase
{
    const IP = '203.0.113.99';

    const RELIABLE = ['keyword', 'linkTld', 'admin'];

    protected function connection(): \Doctrine\DBAL\Connection
    {
        return $this->getApplication()->getServiceManager()->get('Omeka\Connection');
    }

    public function tearDown(): void
    {
        $this->connection()->executeStatement('DELETE FROM `spam_log` WHERE `ip` = :ip', ['ip' => self::IP]);
        parent::tearDown();
    }

    protected function log(): SpamLog
    {
        return $this->getApplication()->getServiceManager()->get('SpamGuard\SpamLog');
    }

    protected function insert(array $reasons, bool $isSpam, string $ago): void
    {
        $this->connection()->insert('spam_log', [
            'ip' => self::IP,
            'source' => 'test',
            'reasons' => implode(',', $reasons),
            'is_spam' => (int) $isSpam,
            'created' => date('Y-m-d H:i:s', strtotime('-' . $ago)),
        ]);
    }

    public function testRecordedSpamIsFound(): void
    {
        $this->log()->record(self::IP, 'contactus', ['tooFast', 'keyword'], true);
        $this->assertTrue($this->log()->hasRecentSpam(self::IP, 24, self::RELIABLE));
    }

    public function testFragileSpamIsIgnored(): void
    {
        $this->log()->record(self::IP, 'contactus', ['tooFast'], true);
        $this->assertFalse($this->log()->hasRecentSpam(self::IP, 24, self::RELIABLE));
    }

    public function testOldSpamIsForgotten(): void
    {
        $this->insert(['keyword'], true, '30 hours');
        $this->assertFalse($this->log()->hasRecentSpam(self::IP, 24, self::RELIABLE));
        $this->assertTrue($this->log()->hasRecentSpam(self::IP, 48, self::RELIABLE));
    }

    /**
     * An admin who decides that a message is not a spam cancels the previous
     * spams of the ip.
     */
    public function testLaterDecisionOfAnAdminCancelsTheReputation(): void
    {
        $this->insert(['keyword'], true, '2 hours');
        $this->insert(['admin'], false, '1 hour');
        $this->assertFalse($this->log()->hasRecentSpam(self::IP, 24, self::RELIABLE));
    }

    /**
     * A spam after the decision of the admin counts again.
     */
    public function testSpamAfterTheDecisionOfAnAdminCounts(): void
    {
        $this->insert(['admin'], false, '2 hours');
        $this->insert(['keyword'], true, '1 hour');
        $this->assertTrue($this->log()->hasRecentSpam(self::IP, 24, self::RELIABLE));
    }

    public function testInvalidIpIsNotRecorded(): void
    {
        $this->log()->record('not-an-ip', 'contactus', ['keyword'], true);
        $this->log()->record(null, 'contactus', ['keyword'], true);
        $count = (int) $this->connection()->executeQuery(
            'SELECT COUNT(*) FROM `spam_log` WHERE `ip` IN ("not-an-ip", "")'
        )->fetchOne();
        $this->assertSame(0, $count);
    }

    /**
     * The checker records the spams with the source given by the module.
     */
    public function testCheckerRecordsTheSpams(): void
    {
        $services = $this->getApplication()->getServiceManager();
        $services->get('Omeka\Settings')->set('spamguard_enabled_strategies', ['honeypot']);
        $checker = $services->build('SpamGuard\SpamChecker');
        $checker->check(new \SpamGuard\SpamContext(ip: self::IP, honeypotValue: 'bot', extra: ['source' => 'comment']));
        $row = $this->connection()->executeQuery(
            'SELECT `source`, `reasons`, `is_spam` FROM `spam_log` WHERE `ip` = :ip',
            ['ip' => self::IP]
        )->fetchAssociative();
        $this->assertSame(['source' => 'comment', 'reasons' => 'honeypot', 'is_spam' => 1], [
            'source' => $row['source'],
            'reasons' => $row['reasons'],
            'is_spam' => (int) $row['is_spam'],
        ]);
    }
}
