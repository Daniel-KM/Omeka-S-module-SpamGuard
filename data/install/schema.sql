CREATE TABLE `spam_log` (
    `id` INT AUTO_INCREMENT NOT NULL,
    `ip` VARCHAR(45) NOT NULL COLLATE `latin1_bin`,
    `source` VARCHAR(190) NOT NULL,
    `reasons` VARCHAR(190) DEFAULT NULL,
    `is_spam` TINYINT(1) NOT NULL,
    `created` DATETIME NOT NULL,
    INDEX `spam_log_ip_idx` (`ip`, `created`),
    INDEX `spam_log_created_idx` (`created`),
    PRIMARY KEY(`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci ENGINE = InnoDB;
