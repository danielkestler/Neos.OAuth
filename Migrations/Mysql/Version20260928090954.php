<?php

declare(strict_types=1);

namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Neos.OAuth: clients and token records
 */
final class Version20260928090954 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Create the tables of the OAuth clients and issued tokens';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\AbstractMySQLPlatform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\AbstractMySQLPlatform'."
        );

        $this->addSql('CREATE TABLE neos_oauth_domain_model_oauthclient (persistence_object_identifier VARCHAR(40) NOT NULL, identifier VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL, secrethash VARCHAR(255) DEFAULT NULL, redirecturis JSON NOT NULL COMMENT \'(DC2Type:json)\', granttypes JSON NOT NULL COMMENT \'(DC2Type:json)\', scopes JSON NOT NULL COMMENT \'(DC2Type:json)\', firstparty TINYINT(1) NOT NULL, accountidentifier VARCHAR(255) DEFAULT NULL, createdat DATETIME NOT NULL COMMENT \'(DC2Type:datetime_immutable)\', UNIQUE INDEX UNIQ_AC8AC39772E836A (identifier), PRIMARY KEY(persistence_object_identifier)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
        $this->addSql('CREATE TABLE neos_oauth_domain_model_tokenrecord (persistence_object_identifier VARCHAR(40) NOT NULL, identifier VARCHAR(255) NOT NULL, type VARCHAR(20) NOT NULL, clientidentifier VARCHAR(255) NOT NULL, accountidentifier VARCHAR(255) DEFAULT NULL, expiresat DATETIME NOT NULL COMMENT \'(DC2Type:datetime_immutable)\', revoked TINYINT(1) NOT NULL, UNIQUE INDEX UNIQ_7265D9AD772E836A (identifier), INDEX IDX_7265D9ADD192F278 (clientidentifier), INDEX IDX_7265D9AD18C8FA2C (accountidentifier), INDEX IDX_7265D9ADBE08598D (expiresat), PRIMARY KEY(persistence_object_identifier)) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB');
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(
            !$this->connection->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\AbstractMySQLPlatform,
            "Migration can only be executed safely on '\Doctrine\DBAL\Platforms\AbstractMySQLPlatform'."
        );

        $this->addSql('DROP TABLE neos_oauth_domain_model_oauthclient');
        $this->addSql('DROP TABLE neos_oauth_domain_model_tokenrecord');
    }
}
