<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain\Repository;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\Repository;
use Neos\OAuth\Domain\Model\OAuthClient;

#[Flow\Scope('singleton')]
class OAuthClientRepository extends Repository
{
    public function findOneByClientIdentifier(string $clientIdentifier): ?OAuthClient
    {
        $query = $this->createQuery();
        /** @var OAuthClient|null $client */
        $client = $query->matching($query->equals('identifier', $clientIdentifier))->execute()->getFirst();
        return $client;
    }
}
