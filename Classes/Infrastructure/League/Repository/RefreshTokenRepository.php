<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Infrastructure\League\Entity\RefreshTokenEntity;

#[Flow\Scope('singleton')]
final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(
        private readonly TokenRecords $tokenRecords,
    ) {
    }

    public function getNewRefreshToken(): RefreshTokenEntity
    {
        return new RefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $accessToken = $refreshTokenEntity->getAccessToken();
        $userIdentifier = $accessToken->getUserIdentifier();
        $this->tokenRecords->add(
            (string)$refreshTokenEntity->getIdentifier(),
            TokenType::REFRESH_TOKEN,
            $accessToken->getClient(),
            $userIdentifier !== null ? (string)$userIdentifier : null,
            $refreshTokenEntity->getExpiryDateTime(),
        );
    }

    public function revokeRefreshToken($tokenId): void
    {
        $this->tokenRecords->revoke((string)$tokenId, TokenType::REFRESH_TOKEN);
    }

    public function isRefreshTokenRevoked($tokenId): bool
    {
        return $this->tokenRecords->isRevoked((string)$tokenId, TokenType::REFRESH_TOKEN);
    }
}
