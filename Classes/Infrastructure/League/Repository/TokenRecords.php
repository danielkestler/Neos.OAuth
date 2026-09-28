<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\OAuth\Domain\Model\TokenRecord;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Domain\Repository\TokenRecordRepository;
use Neos\OAuth\Infrastructure\League\Entity\ClientEntity;

/**
 * Shared bookkeeping of the league token repositories
 *
 * Records are persisted right away: codes are also issued during GET requests, which Flow does not persist on its own
 */
#[Flow\Scope('singleton')]
final class TokenRecords
{
    public function __construct(
        private readonly TokenRecordRepository $tokenRecordRepository,
        private readonly PersistenceManagerInterface $persistenceManager,
    ) {
    }

    public function add(
        string $identifier,
        TokenType $type,
        ClientEntityInterface $client,
        ?string $userIdentifier,
        \DateTimeImmutable $expiresAt,
    ): void {
        if ($this->tokenRecordRepository->findOneByIdentifierAndType($identifier, $type) !== null) {
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }
        $accountIdentifier = $userIdentifier !== null && $userIdentifier !== ''
            ? $userIdentifier
            : ($client instanceof ClientEntity ? $client->accountIdentifier : null);
        $this->tokenRecordRepository->add(new TokenRecord(
            $identifier,
            $type,
            (string)$client->getIdentifier(),
            $accountIdentifier,
            $expiresAt,
        ));
        $this->persistenceManager->persistAll();
    }

    public function revoke(string $identifier, TokenType $type): void
    {
        $record = $this->tokenRecordRepository->findOneByIdentifierAndType($identifier, $type);
        if ($record === null || $record->isRevoked()) {
            return;
        }
        $record->revoke();
        $this->tokenRecordRepository->update($record);
        $this->persistenceManager->persistAll();
    }

    /**
     * Unknown tokens count as revoked
     */
    public function isRevoked(string $identifier, TokenType $type): bool
    {
        $record = $this->tokenRecordRepository->findOneByIdentifierAndType($identifier, $type);
        return $record === null || $record->isRevoked();
    }
}
