<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;

/**
 * The access token of the current request: the account it acts as, and the client and scopes it was issued for
 *
 * The account's roles decide what the caller may do, the scopes can only narrow that down
 */
#[Flow\Proxy(false)]
final readonly class AuthenticatedGrant
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public Account $account,
        public string $clientIdentifier,
        public array $scopes,
    ) {
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * @return list<string> those of the given scopes the token does not grant
     */
    public function missingScopes(string ...$scopes): array
    {
        return array_values(array_diff($scopes, $this->scopes));
    }
}
