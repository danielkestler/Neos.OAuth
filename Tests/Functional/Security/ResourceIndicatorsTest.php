<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Security;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\Token\BearerToken;
use Neos\Flow\Security\Authentication\TokenAndProviderFactoryInterface;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use Neos\OAuth\Infrastructure\League\Entity\UserEntity;
use Neos\OAuth\Infrastructure\League\Repository\ClientRepository;
use Neos\OAuth\Infrastructure\League\Repository\ScopeRepository;
use Neos\OAuth\Infrastructure\League\Repository\TokenRecords;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Neos\OAuth\Security\InvalidTarget;
use Neos\OAuth\Security\ProtectedResources;
use PHPUnit\Framework\Attributes\Test;

/**
 * Tokens bound to resources (RFC 8707), see Configuration/Testing/Settings.yaml for the resources
 */
class ResourceIndicatorsTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    private const string SECRET = 'machine-secret';
    private const string WHOAMI = 'http://localhost/test/neos-oauth';
    private const string STRICT_WHOAMI = 'http://localhost/test/neos-oauth-strict';
    private const string REDIRECT_URI = 'http://localhost/callback';
    private const string CODE_VERIFIER = 'a-code-verifier-that-is-long-enough-for-pkce-0123456789';

    protected function setUp(): void
    {
        parent::setUp();
        foreach (['whoami' => 'test/neos-oauth/whoami', 'strict-whoami' => 'test/neos-oauth-strict/whoami'] as $name => $uriPattern) {
            $this->registerRoute($name, $uriPattern, [
                '@package' => 'Neos.OAuth',
                '@subpackage' => 'Tests\Functional\Fixtures',
                '@controller' => 'Whoami',
                '@action' => 'index',
                '@format' => 'json',
            ]);
        }

        $accountRepository = $this->objectManager->get(AccountRepository::class);
        $accountRepository->add($this->objectManager->get(AccountFactory::class)->createAccountWithPassword('editor', 'password', ['Neos.Neos:Editor'], 'Neos.Neos:Backend'));
        $clientRepository = $this->objectManager->get(OAuthClientRepository::class);
        $clientRepository->add(new OAuthClient('machine', 'Machine', password_hash(self::SECRET, PASSWORD_DEFAULT), [], [OAuthClient::GRANT_CLIENT_CREDENTIALS], ['neos.oauth.test'], false, 'editor'));
        $clientRepository->add(new OAuthClient('spa', 'SPA', null, [self::REDIRECT_URI], [OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN], ['neos.oauth.test'], false, null));
        $this->persistenceManager->persistAll();
    }

    #[Test]
    public function unboundTokensAreAcceptedByResourcesThatDontRequireAnAudience(): void
    {
        $token = $this->clientCredentialsToken();

        self::assertTrue($this->authenticates($token, self::WHOAMI));
        self::assertFalse($this->authenticates($token, self::STRICT_WHOAMI));
    }

    #[Test]
    public function boundTokensAreOnlyAcceptedByTheirResources(): void
    {
        $token = $this->clientCredentialsToken(self::STRICT_WHOAMI);

        self::assertTrue($this->authenticates($token, self::STRICT_WHOAMI));
        self::assertFalse($this->authenticates($token, self::WHOAMI));
    }

    #[Test]
    public function tokensCanBeBoundToSeveralResources(): void
    {
        $token = $this->clientCredentialsToken(self::WHOAMI, self::STRICT_WHOAMI . '/');

        self::assertTrue($this->authenticates($token, self::WHOAMI));
        self::assertTrue($this->authenticates($token, self::STRICT_WHOAMI));
    }

    #[Test]
    public function unknownResourcesAreRejected(): void
    {
        $response = $this->tokenRequest(['grant_type' => 'client_credentials', 'client_id' => 'machine', 'client_secret' => self::SECRET, 'scope' => 'neos.oauth.test'], 'http://example.com/api');

        self::assertSame(400, $response['status']);
        self::assertSame('invalid_target', $response['body']['error']);
    }

    #[Test]
    public function tokensInheritTheAudienceOfTheCodeAndRefreshToken(): void
    {
        $response = $this->exchangeCode($this->authorizationCode([self::STRICT_WHOAMI]));
        self::assertSame(200, $response['status'], json_encode($response['body']));
        self::assertTrue($this->authenticates($response['body']['access_token'], self::STRICT_WHOAMI));
        self::assertFalse($this->authenticates($response['body']['access_token'], self::WHOAMI));

        $refreshed = $this->tokenRequest(['grant_type' => 'refresh_token', 'client_id' => 'spa', 'refresh_token' => $response['body']['refresh_token']]);
        self::assertSame(200, $refreshed['status'], json_encode($refreshed['body']));
        self::assertTrue($this->authenticates($refreshed['body']['access_token'], self::STRICT_WHOAMI));
        self::assertFalse($this->authenticates($refreshed['body']['access_token'], self::WHOAMI));
    }

    #[Test]
    public function theTokenRequestCanNarrowTheAudienceButNotWidenIt(): void
    {
        $narrowed = $this->exchangeCode($this->authorizationCode([self::WHOAMI, self::STRICT_WHOAMI]), self::STRICT_WHOAMI);
        self::assertSame(200, $narrowed['status'], json_encode($narrowed['body']));
        self::assertFalse($this->authenticates($narrowed['body']['access_token'], self::WHOAMI));

        $widened = $this->exchangeCode($this->authorizationCode([self::STRICT_WHOAMI]), self::WHOAMI);
        self::assertSame(400, $widened['status']);
        self::assertSame('invalid_target', $widened['body']['error']);
    }

    #[Test]
    public function repeatedResourceParametersAreAllRead(): void
    {
        self::assertSame(
            ['http://localhost/a', 'http://localhost/b c'],
            ProtectedResources::indicatorsIn('client_id=x&resource=http%3A%2F%2Flocalhost%2Fa&scope=y&resource=http://localhost/b+c&resource='),
        );
    }

    #[Test]
    public function resourceIndicatorsMustNameProtectedResources(): void
    {
        $protectedResources = $this->objectManager->get(ProtectedResources::class);
        self::assertSame([self::WHOAMI], $protectedResources->audienceFor([self::WHOAMI . '/', self::WHOAMI]));
        self::assertSame([], $protectedResources->audienceFor([]));

        $this->expectException(InvalidTarget::class);
        $protectedResources->audienceFor([self::WHOAMI . '/whoami']);
    }

    private function clientCredentialsToken(string ...$resources): string
    {
        $response = $this->tokenRequest(['grant_type' => 'client_credentials', 'client_id' => 'machine', 'client_secret' => self::SECRET, 'scope' => 'neos.oauth.test'], ...$resources);
        self::assertSame(200, $response['status'], json_encode($response['body']));
        return $response['body']['access_token'];
    }

    /**
     * Issues a code as the AuthorizeController does once the user approved, without the login and consent pages
     *
     * @param list<string> $audience
     */
    private function authorizationCode(array $audience): string
    {
        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setGrantTypeId('authorization_code');
        $authorizationRequest->setClient($this->objectManager->get(ClientRepository::class)->getClientEntity('spa'));
        $authorizationRequest->setUser(new UserEntity('editor'));
        $authorizationRequest->setScopes([$this->objectManager->get(ScopeRepository::class)->getScopeEntityByIdentifier('neos.oauth.test')]);
        $authorizationRequest->setRedirectUri(self::REDIRECT_URI);
        $authorizationRequest->setCodeChallenge(rtrim(strtr(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '+/', '-_'), '='));
        $authorizationRequest->setCodeChallengeMethod('S256');
        $authorizationRequest->setAuthorizationApproved(true);

        $response = $this->objectManager->get(TokenRecords::class)->withAudience($audience, fn () => $this->objectManager->get(ServerFactory::class)
            ->getAuthorizationServer()->completeAuthorizationRequest($authorizationRequest, new Response()));
        parse_str((string)parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        self::assertIsString($query['code'] ?? null, $response->getHeaderLine('Location'));
        return $query['code'];
    }

    /**
     * @return array{status: int, body: array<string, mixed>}
     */
    private function exchangeCode(string $code, string ...$resources): array
    {
        return $this->tokenRequest(['grant_type' => 'authorization_code', 'client_id' => 'spa', 'code' => $code, 'redirect_uri' => self::REDIRECT_URI, 'code_verifier' => self::CODE_VERIFIER], ...$resources);
    }

    /**
     * Sends the parameters form-encoded, with a "resource" parameter per resource
     *
     * @param array<string, string> $parameters
     * @return array{status: int, body: array<string, mixed>}
     */
    private function tokenRequest(array $parameters, string ...$resources): array
    {
        $body = http_build_query($parameters);
        foreach ($resources as $resource) {
            $body .= '&resource=' . rawurlencode($resource);
        }
        $response = $this->browser->sendRequest(new ServerRequest('POST', 'http://localhost/oauth/token', ['Content-Type' => 'application/x-www-form-urlencoded'], $body));
        return ['status' => $response->getStatusCode(), 'body' => json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)];
    }

    private function authenticates(string $bearer, string $resource): bool
    {
        $this->resetAuthenticationState();
        $response = $this->browser->sendRequest(new ServerRequest('GET', $resource . '/whoami', ['Authorization' => 'Bearer ' . $bearer]));
        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        return json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)['authenticated'];
    }

    /**
     * The browser runs all requests in one process: forget the previous request's authentication
     */
    private function resetAuthenticationState(): void
    {
        $this->inject($this->objectManager->get(AuthenticationManagerInterface::class), 'isAuthenticated', null);
        foreach ($this->objectManager->get(TokenAndProviderFactoryInterface::class)->getTokens() as $token) {
            if ($token instanceof BearerToken) {
                $this->inject($token, 'credentials', ['bearer' => '']);
            }
        }
    }
}
