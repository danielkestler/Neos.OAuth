<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Security\Authentication\Token\BearerToken;

/**
 * An OAuth access token sent as "Authorization: Bearer …"
 *
 * Once authenticated, it carries the account the token was issued for and what the token grants on top of that
 * account's roles: the client that requested it and its scopes. Packages that accept the tokens read them from here
 */
class OAuthBearerToken extends BearerToken
{
    /**
     * @var list<string>
     */
    protected array $scopes = [];

    protected ?string $clientIdentifier = null;

    protected ?string $accessTokenIdentifier = null;

    /**
     * @param list<string> $scopes
     * @param string|null $accessTokenIdentifier the identifier of the access token's TokenRecord
     * @internal set by the OAuthBearerProvider
     */
    public function setGrant(string $clientIdentifier, array $scopes, ?string $accessTokenIdentifier = null): void
    {
        $this->clientIdentifier = $clientIdentifier;
        $this->scopes = array_values($scopes);
        $this->accessTokenIdentifier = $accessTokenIdentifier;
    }

    /**
     * @return list<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function getClientIdentifier(): ?string
    {
        return $this->clientIdentifier;
    }

    /**
     * The identifier of the access token's TokenRecord, e.g. to revoke the account's other tokens but this one
     */
    public function getAccessTokenIdentifier(): ?string
    {
        return $this->accessTokenIdentifier;
    }

    public function __toString(): string
    {
        return 'OAuth bearer token';
    }
}
