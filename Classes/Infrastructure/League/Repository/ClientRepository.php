<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\ClientDirectory;
use Neos\OAuth\Infrastructure\League\Entity\ClientEntity;

#[Flow\Scope('singleton')]
final class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(
        private readonly ClientDirectory $clients,
    ) {
    }

    public function getClientEntity($clientIdentifier): ?ClientEntity
    {
        $client = $this->clients->find((string)$clientIdentifier);
        return $client !== null ? ClientEntity::fromModel($client) : null;
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $client = $this->clients->find((string)$clientIdentifier);
        if ($client === null) {
            return false;
        }
        if ($grantType === null || !$client->allowsGrantType((string)$grantType)) {
            return false;
        }
        if ($client->isConfidential()) {
            return is_string($clientSecret) && $clientSecret !== '' && $client->validateSecret($clientSecret);
        }
        // Public clients have no secret. They may only use grants that are bound by PKCE or a refresh token
        return $grantType !== OAuthClient::GRANT_CLIENT_CREDENTIALS;
    }
}
