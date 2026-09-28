<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\ScopeRegistry;
use Neos\OAuth\Infrastructure\League\Entity\ClientEntity;
use Neos\OAuth\Infrastructure\League\Entity\ScopeEntity;

#[Flow\Scope('singleton')]
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        private readonly ScopeRegistry $scopeRegistry,
    ) {
    }

    public function getScopeEntityByIdentifier($identifier): ?ScopeEntity
    {
        return $this->scopeRegistry->isKnown((string)$identifier) ? new ScopeEntity((string)$identifier) : null;
    }

    /**
     * Only scopes the client is allowed to request are granted, the others are dropped silently
     */
    public function finalizeScopes(array $scopes, $grantType, ClientEntityInterface $clientEntity, $userIdentifier = null): array
    {
        $allowed = $clientEntity instanceof ClientEntity ? $clientEntity->scopes : [];
        return array_values(array_filter(
            $scopes,
            fn ($scope) => in_array($scope->getIdentifier(), $allowed, true) && $this->scopeRegistry->isKnown($scope->getIdentifier()),
        ));
    }
}
