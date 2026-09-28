<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain\Repository;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Doctrine\Repository;
use Neos\OAuth\Domain\Model\TokenRecord;
use Neos\OAuth\Domain\Model\TokenType;

#[Flow\Scope('singleton')]
class TokenRecordRepository extends Repository
{
    public function findOneByIdentifierAndType(string $identifier, TokenType $type): ?TokenRecord
    {
        /** @var TokenRecord|null $record */
        $record = $this->findOneBy(['identifier' => $identifier, 'type' => $type->value]);
        return $record;
    }

    /**
     * @return list<TokenRecord>
     */
    public function findActive(?string $clientIdentifier, ?string $accountIdentifier, \DateTimeImmutable $now): array
    {
        $queryBuilder = $this->createQueryBuilder('t')
            ->where('t.revoked = false')
            ->andWhere('t.expiresAt > :now')
            ->setParameter('now', $now)
            ->orderBy('t.expiresAt', 'ASC');
        if ($clientIdentifier !== null) {
            $queryBuilder->andWhere('t.clientIdentifier = :clientIdentifier')->setParameter('clientIdentifier', $clientIdentifier);
        }
        if ($accountIdentifier !== null) {
            $queryBuilder->andWhere('t.accountIdentifier = :accountIdentifier')->setParameter('accountIdentifier', $accountIdentifier);
        }
        return $queryBuilder->getQuery()->getResult();
    }

    public function removeExpired(\DateTimeImmutable $now): int
    {
        return (int)$this->createQueryBuilder('t')
            ->delete()
            ->where('t.expiresAt <= :now')
            ->setParameter('now', $now)
            ->getQuery()
            ->execute();
    }
}
