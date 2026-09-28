<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Infrastructure\League\Entity\AccessTokenEntity;

#[Flow\Scope('singleton')]
final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(
        private readonly TokenRecords $tokenRecords,
    ) {
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): AccessTokenEntity
    {
        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }
        if ($userIdentifier !== null) {
            $accessToken->setUserIdentifier($userIdentifier);
        }
        return $accessToken;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $userIdentifier = $accessTokenEntity->getUserIdentifier();
        $this->tokenRecords->add(
            (string)$accessTokenEntity->getIdentifier(),
            TokenType::ACCESS_TOKEN,
            $accessTokenEntity->getClient(),
            $userIdentifier !== null ? (string)$userIdentifier : null,
            $accessTokenEntity->getExpiryDateTime(),
        );
    }

    public function revokeAccessToken($tokenId): void
    {
        $this->tokenRecords->revoke((string)$tokenId, TokenType::ACCESS_TOKEN);
    }

    public function isAccessTokenRevoked($tokenId): bool
    {
        return $this->tokenRecords->isRevoked((string)$tokenId, TokenType::ACCESS_TOKEN);
    }
}
