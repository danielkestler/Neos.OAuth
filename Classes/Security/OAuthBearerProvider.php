<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\OAuth\Domain\ClientDirectory;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Psr\Log\LoggerInterface;

/**
 * Authenticates OAuth access tokens as the Flow account they were issued for
 *
 * The token then has that account's roles, so policies apply exactly as in a backend session. Scopes can only narrow
 * that down, it's up to the consuming package to check them
 */
class OAuthBearerProvider extends AbstractProvider
{
    #[Flow\Inject]
    protected ServerFactory $serverFactory;

    #[Flow\Inject]
    protected ClientDirectory $clientDirectory;

    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    #[Flow\Inject]
    protected LoggerInterface $logger;

    #[Flow\InjectConfiguration(path: 'accountAuthenticationProviderName', package: 'Neos.OAuth')]
    protected string $accountAuthenticationProviderName;

    public function getTokenClassNames(): array
    {
        return [OAuthBearerToken::class];
    }

    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OAuthBearerToken) {
            throw new UnsupportedAuthenticationTokenException(sprintf('This provider cannot authenticate %s', get_class($authenticationToken)), 1790100020);
        }
        $bearer = $authenticationToken->getBearer();
        if ($bearer === '') {
            $authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            return;
        }

        try {
            // checks signature, expiry and revocation
            $validatedRequest = $this->serverFactory->getResourceServer()->validateAuthenticatedRequest(
                new ServerRequest('GET', '/', ['Authorization' => 'Bearer ' . $bearer])
            );
        } catch (OAuthServerException $exception) {
            $this->logger->debug(sprintf('Rejected OAuth access token: %s', $exception->getHint() ?? $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $clientIdentifier = (string)$validatedRequest->getAttribute('oauth_client_id');
        $client = $this->clientDirectory->find($clientIdentifier);
        if ($client === null) {
            $this->logger->info(sprintf('Rejected OAuth access token of the removed client "%s"', $clientIdentifier), LogEnvironment::fromMethodName(__METHOD__));
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        // Tokens of the client_credentials grant have no user, they act as the account configured for the client
        $userIdentifier = (string)$validatedRequest->getAttribute('oauth_user_id');
        $accountIdentifier = $userIdentifier !== '' ? $userIdentifier : $client->getAccountIdentifier();
        $account = $accountIdentifier !== null
            ? $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $this->accountAuthenticationProviderName)
            : null;
        if ($account === null) {
            $this->logger->info(sprintf('Rejected OAuth access token of client "%s": no active account "%s"', $clientIdentifier, $accountIdentifier ?? ''), LogEnvironment::fromMethodName(__METHOD__));
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $authenticationToken->setGrant($clientIdentifier, array_values(array_map('strval', (array)$validatedRequest->getAttribute('oauth_scopes', []))));
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
    }
}
