<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Context as SecurityContext;

/**
 * Tells packages that accept the tokens who the current request's access token belongs to
 *
 * Only requests matching a request pattern of the Neos.OAuth:Bearer provider are considered, see Settings.yaml
 */
#[Flow\Scope('singleton')]
final class OAuthContext
{
    /**
     * The name of the authentication provider, see Settings.yaml
     */
    public const string PROVIDER_NAME = 'Neos.OAuth:Bearer';

    public function __construct(
        private readonly AuthenticationManagerInterface $authenticationManager,
        private readonly SecurityContext $securityContext,
    ) {
    }

    /**
     * The grant of a valid access token sent with the current request, or null if there is none
     */
    public function authenticatedGrant(): ?AuthenticatedGrant
    {
        // Flow only collects the credentials, this authenticates them without throwing if there are none
        $this->authenticationManager->isAuthenticated();
        foreach ($this->securityContext->getAuthenticationTokensOfType(OAuthBearerToken::class) as $token) {
            $account = $token->getAccount();
            if ($token->getAuthenticationProviderName() === self::PROVIDER_NAME && $token->isAuthenticated() && $account !== null) {
                return new AuthenticatedGrant($account, (string)$token->getClientIdentifier(), $token->getScopes());
            }
        }
        return null;
    }
}
