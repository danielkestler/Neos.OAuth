<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Infrastructure\League\Entity\AuthCodeEntity;

#[Flow\Scope('singleton')]
final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(
        private readonly TokenRecords $tokenRecords,
    ) {
    }

    public function getNewAuthCode(): AuthCodeEntity
    {
        return new AuthCodeEntity();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $userIdentifier = $authCodeEntity->getUserIdentifier();
        $this->tokenRecords->add(
            (string)$authCodeEntity->getIdentifier(),
            TokenType::AUTH_CODE,
            $authCodeEntity->getClient(),
            $userIdentifier !== null ? (string)$userIdentifier : null,
            $authCodeEntity->getExpiryDateTime(),
        );
    }

    public function revokeAuthCode($codeId): void
    {
        $this->tokenRecords->revoke((string)$codeId, TokenType::AUTH_CODE);
    }

    public function isAuthCodeRevoked($codeId): bool
    {
        return $this->tokenRecords->isRevoked((string)$codeId, TokenType::AUTH_CODE);
    }
}
