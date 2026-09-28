<?php
declare(strict_types=1);

namespace Neos\OAuth\Controller;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\ScopeRegistry;
use Neos\OAuth\Infrastructure\League\Entity\ClientEntity;
use Neos\OAuth\Infrastructure\League\Entity\UserEntity;
use Neos\OAuth\Infrastructure\League\LeagueResponse;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The authorization endpoint (RFC 6749 section 3.1) of the authorization code grant
 *
 * The logged in backend user is asked to approve the client's request. PKCE with S256 is required from every client
 */
class AuthorizeController extends ActionController
{
    private const string TEMPLATE = 'resource://Neos.OAuth/Private/Templates/Authorize/Page.html';

    #[Flow\Inject]
    protected ServerFactory $serverFactory;

    #[Flow\Inject]
    protected ScopeRegistry $scopeRegistry;

    #[Flow\Inject]
    protected AuthenticationManagerInterface $authenticationManager;

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    #[Flow\InjectConfiguration(path: 'accountAuthenticationProviderName', package: 'Neos.OAuth')]
    protected string $accountAuthenticationProviderName;

    public function authorizeAction(): ResponseInterface
    {
        $account = $this->authenticatedAccount();
        if ($account === null) {
            // The login form sends the user back here, see the route's appendExceedingArguments
            throw (new AuthenticationRequiredException('Log in to authorize the client', 1790100030))->attachInterceptedRequest($this->request);
        }

        $httpRequest = $this->request->getHttpRequest();
        try {
            $authorizationRequest = $this->validate($httpRequest);
            $client = $authorizationRequest->getClient();
            if ($client instanceof ClientEntity && $client->firstParty) {
                return $this->complete($authorizationRequest, $account, true);
            }
        } catch (OAuthServerException $exception) {
            return $this->errorResponse($exception);
        }

        return $this->renderPage(200, [
            'clientName' => $client->getName(),
            'scopes' => $this->describe($authorizationRequest),
            'accountIdentifier' => $account->getAccountIdentifier(),
            'authorizationQuery' => $httpRequest->getUri()->getQuery(),
        ]);
    }

    /**
     * @param string $authorizationQuery the query string of the authorization request the user decided on
     * @param string $decision "approve" or anything else to deny
     */
    public function decideAction(string $authorizationQuery, string $decision): ResponseInterface
    {
        $account = $this->authenticatedAccount();
        if ($account === null) {
            return $this->renderPage(401, ['error' => 'Your session has expired. Please start the authorization again.']);
        }
        parse_str($authorizationQuery, $queryParameters);
        try {
            // Validated again, the form's values cannot be trusted
            $authorizationRequest = $this->validate(
                (new ServerRequest('GET', '/oauth/authorize?' . $authorizationQuery))->withQueryParams($queryParameters)
            );
            return $this->complete($authorizationRequest, $account, $decision === 'approve');
        } catch (OAuthServerException $exception) {
            return $this->errorResponse($exception);
        }
    }

    private function validate(ServerRequestInterface $request): AuthorizationRequest
    {
        $authorizationServer = $this->serverFactory->getAuthorizationServer();
        $authorizationRequest = $authorizationServer->validateAuthorizationRequest($request);

        // From here on, the redirect URI is known to belong to the client, so errors are sent there
        $client = $authorizationRequest->getClient();
        $redirectUri = $authorizationRequest->getRedirectUri() ?? ((array)$client->getRedirectUri())[0] ?? null;
        $state = $authorizationRequest->getState();
        if ($redirectUri !== null && $state !== null) {
            $redirectUri .= (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query(['state' => $state]);
        }

        if (!$client instanceof ClientEntity || !$client->allowsGrantType(OAuthClient::GRANT_AUTHORIZATION_CODE)) {
            throw new OAuthServerException('The client is not authorized to request an authorization code using this method.', 9, 'unauthorized_client', 400, null, $redirectUri);
        }
        if ($authorizationRequest->getCodeChallenge() === null || $authorizationRequest->getCodeChallengeMethod() !== 'S256') {
            throw new OAuthServerException('The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.', 3, 'invalid_request', 400, 'PKCE with code_challenge_method "S256" is required', $redirectUri);
        }
        return $authorizationRequest;
    }

    private function complete(AuthorizationRequest $authorizationRequest, Account $account, bool $approved): ResponseInterface
    {
        $authorizationRequest->setUser(new UserEntity($account->getAccountIdentifier()));
        $authorizationRequest->setAuthorizationApproved($approved);
        return LeagueResponse::rewound($this->serverFactory->getAuthorizationServer()->completeAuthorizationRequest($authorizationRequest, new Response()));
    }

    private function authenticatedAccount(): ?Account
    {
        $this->authenticationManager->isAuthenticated();
        foreach ($this->securityContext->getAuthenticationTokens() as $token) {
            if ($token->getAuthenticationProviderName() === $this->accountAuthenticationProviderName && $token->isAuthenticated()) {
                return $token->getAccount();
            }
        }
        return null;
    }

    /**
     * @return list<array{identifier: string, description: string}>
     */
    private function describe(AuthorizationRequest $authorizationRequest): array
    {
        $scopes = [];
        foreach ($authorizationRequest->getScopes() as $scope) {
            $identifier = (string)$scope->getIdentifier();
            $scopes[] = ['identifier' => $identifier, 'description' => $this->scopeRegistry->describe($identifier)];
        }
        return $scopes;
    }

    private function errorResponse(OAuthServerException $exception): ResponseInterface
    {
        if ($exception->hasRedirect()) {
            return LeagueResponse::rewound($exception->generateHttpResponse(new Response()));
        }
        // Without a verified redirect URI, the error must not be sent anywhere
        $this->logger->info(sprintf('Rejected OAuth authorization request: %s', $exception->getHint() ?? $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
        return $this->renderPage($exception->getHttpStatusCode(), [
            'error' => $exception->getMessage(),
            'hint' => $exception->getHint(),
        ]);
    }

    /**
     * @param array<string, mixed> $variables
     */
    private function renderPage(int $statusCode, array $variables): ResponseInterface
    {
        $this->view->setTemplatePathAndFilename(self::TEMPLATE);
        $this->view->assignMultiple($variables);
        return new Response($statusCode, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store',
            'X-Frame-Options' => 'DENY',
            'Content-Security-Policy' => "frame-ancestors 'none'",
        ], (string)$this->view->render());
    }
}
