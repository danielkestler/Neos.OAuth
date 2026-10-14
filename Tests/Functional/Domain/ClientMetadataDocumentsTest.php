<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Domain;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\Token\BearerToken;
use Neos\Flow\Security\Authentication\TokenAndProviderFactoryInterface;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Controller\AuthorizeController;
use Neos\OAuth\Domain\ClientDirectory;
use Neos\OAuth\Domain\ClientMetadataDocuments;
use Neos\OAuth\Domain\InvalidClientMetadataDocument;
use Neos\OAuth\Infrastructure\Http\ClientMetadataDocumentNotFetched;
use Neos\OAuth\Infrastructure\Http\GuzzleClientMetadataDocumentFetcher;
use Neos\OAuth\Infrastructure\Http\FetchedDocument;
use Neos\OAuth\Infrastructure\League\Entity\UserEntity;
use Neos\OAuth\Infrastructure\League\Repository\TokenRecords;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Neos\OAuth\Tests\Functional\Fixtures\FakeClientMetadataDocumentFetcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Clients identified by the URL of their metadata document, served by the FakeClientMetadataDocumentFetcher
 */
class ClientMetadataDocumentsTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    private const string CLIENT_ID = 'https://client.example.com/oauth/metadata.json';
    private const string REDIRECT_URI = 'http://localhost/callback';
    private const string STRICT_WHOAMI = 'http://localhost/test/neos-oauth-strict';
    private const string CODE_VERIFIER = 'a-code-verifier-that-is-long-enough-for-pkce-0123456789';

    private FakeClientMetadataDocumentFetcher $fetcher;

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
        $this->objectManager->get(AccountRepository::class)->add($this->objectManager->get(AccountFactory::class)->createAccountWithPassword('editor', 'password', ['Neos.Neos:Editor'], 'Neos.Neos:Backend'));
        $this->persistenceManager->persistAll();

        $this->fetcher = $this->objectManager->get(FakeClientMetadataDocumentFetcher::class);
        $this->fetcher->reset();
        $this->fetcher->serve(self::CLIENT_ID, self::document());
        $this->objectManager->get(CacheManager::class)->getCache('Neos_OAuth_ClientMetadataDocuments')->flush();
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        $this->enable(true);
    }

    protected function tearDown(): void
    {
        $this->enable(false);
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        parent::tearDown();
    }

    #[Test]
    public function theDiscoveryDocumentAdvertisesSupportWhenEnabled(): void
    {
        self::assertTrue($this->discoveryDocument()['client_id_metadata_document_supported'] ?? null);

        $this->enable(false);
        self::assertArrayNotHasKey('client_id_metadata_document_supported', $this->discoveryDocument());
    }

    #[Test]
    public function clientsAreBuiltFromTheirDocument(): void
    {
        $client = $this->objectManager->get(ClientDirectory::class)->find(self::CLIENT_ID);

        self::assertNotNull($client);
        self::assertSame('Example MCP client', $client->getName());
        self::assertFalse($client->isConfidential());
        self::assertFalse($client->isFirstParty());
        self::assertNull($client->getAccountIdentifier());
        self::assertSame([self::REDIRECT_URI, 'http://127.0.0.1/callback'], $client->getRedirectUris());
        self::assertSame(['authorization_code', 'refresh_token'], $client->getGrantTypes());
        self::assertContains('neos.oauth.test', $client->getScopes());
        self::assertContains('neos.oauth.provided', $client->getScopes());
    }

    /**
     * As ChatGPT's document (https://chatgpt.com/oauth/client.json): it prefers private_key_jwt, but supports "none"
     */
    #[Test]
    public function clientsThatAlsoSupportNoClientAuthenticationArePublicClients(): void
    {
        $this->fetcher->serve(self::CLIENT_ID, self::document([
            'token_endpoint_auth_method' => 'private_key_jwt',
            'token_endpoint_auth_methods_supported' => ['none', 'private_key_jwt'],
            'token_endpoint_auth_signing_alg' => 'RS256',
            'jwks_uri' => 'https://client.example.com/jwks.json',
        ]));

        $client = $this->objectManager->get(ClientDirectory::class)->find(self::CLIENT_ID);

        self::assertNotNull($client);
        self::assertFalse($client->isConfidential());
    }

    #[Test]
    public function theScopeOfTheDocumentLimitsTheScopes(): void
    {
        $this->fetcher->serve(self::CLIENT_ID, self::document(['scope' => 'neos.oauth.test unknown']));

        self::assertSame(['neos.oauth.test'], $this->objectManager->get(ClientDirectory::class)->find(self::CLIENT_ID)?->getScopes());
    }

    #[Test]
    public function clientsGetCodesAndTokensBoundToResources(): void
    {
        // any port of a localhost redirect URI (RFC 8252)
        $redirectUri = 'http://localhost:54321/callback';
        $code = $this->authorizationCode($redirectUri, [self::STRICT_WHOAMI]);

        $response = $this->tokenRequest(['grant_type' => 'authorization_code', 'client_id' => self::CLIENT_ID, 'code' => $code, 'redirect_uri' => $redirectUri, 'code_verifier' => self::CODE_VERIFIER]);
        self::assertSame(200, $response['status'], json_encode($response['body']));
        self::assertTrue($this->authenticates($response['body']['access_token'], self::STRICT_WHOAMI));
        self::assertFalse($this->authenticates($response['body']['access_token'], 'http://localhost/test/neos-oauth'));

        $refreshed = $this->tokenRequest(['grant_type' => 'refresh_token', 'client_id' => self::CLIENT_ID, 'refresh_token' => $response['body']['refresh_token']]);
        self::assertSame(200, $refreshed['status'], json_encode($refreshed['body']));
        self::assertTrue($this->authenticates($refreshed['body']['access_token'], self::STRICT_WHOAMI));
        // all from the cache
        self::assertSame(1, $this->fetcher->fetches[self::CLIENT_ID]);
    }

    #[Test]
    public function tokensAreRejectedOnceTheDocumentIsGone(): void
    {
        $response = $this->tokenRequest(['grant_type' => 'authorization_code', 'client_id' => self::CLIENT_ID, 'code' => $this->authorizationCode(self::REDIRECT_URI, [self::STRICT_WHOAMI]), 'redirect_uri' => self::REDIRECT_URI, 'code_verifier' => self::CODE_VERIFIER]);
        self::assertSame(200, $response['status'], json_encode($response['body']));

        $this->fetcher->fail(self::CLIENT_ID, new ClientMetadataDocumentNotFetched('The server responded with status 404', 1));
        $this->expire();

        self::assertFalse($this->authenticates($response['body']['access_token'], self::STRICT_WHOAMI));
    }

    #[Test]
    public function documentsAreCached(): void
    {
        $directory = $this->objectManager->get(ClientDirectory::class);
        self::assertNotNull($directory->find(self::CLIENT_ID));
        // as in a later request
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        self::assertNotNull($directory->find(self::CLIENT_ID));

        self::assertSame(1, $this->fetcher->fetches[self::CLIENT_ID]);
    }

    #[Test]
    public function outdatedDocumentsAreUsedWhileTheyCannotBeFetchedTemporarily(): void
    {
        $directory = $this->objectManager->get(ClientDirectory::class);
        self::assertNotNull($directory->find(self::CLIENT_ID));

        $this->fetcher->fail(self::CLIENT_ID, ClientMetadataDocumentNotFetched::temporarily('timeout', 1));
        $this->expire();
        self::assertNotNull($directory->find(self::CLIENT_ID));
        self::assertSame(2, $this->fetcher->fetches[self::CLIENT_ID]);

        // not tried again on every request
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        self::assertNotNull($directory->find(self::CLIENT_ID));
        self::assertSame(2, $this->fetcher->fetches[self::CLIENT_ID]);
    }

    #[Test]
    public function failuresAreCachedBriefly(): void
    {
        $this->fetcher->fail(self::CLIENT_ID, ClientMetadataDocumentNotFetched::temporarily('timeout', 1));
        $directory = $this->objectManager->get(ClientDirectory::class);
        self::assertNull($directory->find(self::CLIENT_ID));
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        self::assertNull($directory->find(self::CLIENT_ID));

        self::assertSame(1, $this->fetcher->fetches[self::CLIENT_ID]);
    }

    #[Test]
    public function urlClientIdsAreUnknownWhenDisabled(): void
    {
        $this->enable(false);

        self::assertNull($this->objectManager->get(ClientDirectory::class)->find(self::CLIENT_ID));
        self::assertSame([], $this->fetcher->fetches);
        self::assertStringContainsString('does not support', $this->authorizationError(self::CLIENT_ID, self::REDIRECT_URI)->getHint());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidClientIds(): iterable
    {
        yield 'http' => ['http://client.example.com/metadata.json'];
        yield 'no path' => ['https://client.example.com'];
        yield 'fragment' => ['https://client.example.com/metadata.json#x'];
        yield 'credentials' => ['https://user:secret@client.example.com/metadata.json'];
        yield 'dot segment' => ['https://client.example.com/a/../metadata.json'];
        yield 'encoded dot segment' => ['https://client.example.com/a/%2E%2E/metadata.json'];
        yield 'too long' => ['https://client.example.com/' . str_repeat('a', 240)];
    }

    #[Test]
    #[DataProvider('invalidClientIds')]
    public function invalidClientIdsAreNotFetched(string $clientId): void
    {
        $this->fetcher->serve($clientId, self::document(['client_id' => $clientId]));

        self::assertStringContainsString('no valid metadata document URL', $this->problemWith($clientId));
        self::assertSame([], $this->fetcher->fetches);
    }

    /**
     * @return iterable<string, array{array<string, mixed>|string, string}>
     */
    public static function invalidDocuments(): iterable
    {
        yield 'no JSON' => ['<html></html>', 'no valid JSON'];
        yield 'no object' => [[self::CLIENT_ID], 'JSON object'];
        yield 'other client_id' => [self::document(['client_id' => 'https://evil.example.com/metadata.json']), 'client_id'];
        yield 'no client_name' => [self::document(['client_name' => null]), 'client_name'];
        yield 'no redirect_uris' => [self::document(['redirect_uris' => []]), 'redirect_uris'];
        yield 'http redirect URI' => [self::document(['redirect_uris' => ['http://example.com/callback']]), 'Invalid redirect URI'];
        yield 'private_key_jwt' => [self::document(['token_endpoint_auth_method' => 'private_key_jwt']), 'only public clients'];
        yield 'private_key_jwt only' => [self::document(['token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_methods_supported' => ['private_key_jwt']]), 'only public clients'];
        yield 'secret' => [self::document(['client_secret' => 'secret']), 'only public clients'];
        yield 'client_credentials' => [self::document(['grant_types' => ['authorization_code', 'client_credentials']]), 'grant_types'];
        yield 'too large' => [self::document(['padding' => str_repeat('x', 70000)]), 'larger than'];
    }

    /**
     * @param array<string, mixed>|string $document
     */
    #[Test]
    #[DataProvider('invalidDocuments')]
    public function invalidDocumentsAreRejected(array|string $document, string $problem): void
    {
        $this->fetcher->serve(self::CLIENT_ID, $document);

        self::assertStringContainsString($problem, $this->problemWith(self::CLIENT_ID));
        self::assertNull($this->objectManager->get(ClientDirectory::class)->find(self::CLIENT_ID));
    }

    #[Test]
    public function theAuthorizationEndpointExplainsProblemsWithoutRedirecting(): void
    {
        $exception = $this->authorizationError(self::CLIENT_ID, 'http://localhost/other');
        self::assertSame('invalid_client', $exception->getErrorType());
        self::assertFalse($exception->hasRedirect());
        self::assertStringContainsString('redirect_uris in the client metadata document', $exception->getHint());

        $this->fetcher->serve(self::CLIENT_ID, self::document(['client_id' => 'https://evil.example.com/metadata.json']));
        $this->objectManager->get(CacheManager::class)->getCache('Neos_OAuth_ClientMetadataDocuments')->flush();
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        $exception = $this->authorizationError(self::CLIENT_ID, self::REDIRECT_URI);
        self::assertFalse($exception->hasRedirect());
        self::assertStringContainsString('its client_id must be its own URL', $exception->getHint());
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function addresses(): iterable
    {
        yield 'public IPv4' => ['93.184.215.14', true];
        yield 'public IPv6' => ['2606:2800:21f:cb07:6820:80da:af6b:8b2c', true];
        yield 'loopback' => ['127.0.0.1', false];
        yield 'private 10' => ['10.1.2.3', false];
        yield 'private 172' => ['172.20.0.1', false];
        yield 'private 192' => ['192.168.1.1', false];
        yield 'link-local / cloud metadata' => ['169.254.169.254', false];
        yield 'shared address space' => ['100.64.0.1', false];
        yield 'unspecified' => ['0.0.0.0', false];
        yield 'multicast' => ['224.0.0.1', false];
        yield 'broadcast' => ['255.255.255.255', false];
        yield 'IPv6 loopback' => ['::1', false];
        yield 'IPv6 unique local' => ['fd00::1', false];
        yield 'IPv6 link-local' => ['fe80::1', false];
        yield 'IPv4-mapped private' => ['::ffff:10.0.0.1', false];
        yield 'IPv4-mapped public' => ['::ffff:93.184.215.14', true];
        yield 'NAT64' => ['64:ff9b::a00:1', false];
        yield '6to4' => ['2002:a00:1::1', false];
        yield 'documentation' => ['2001:db8::1', false];
        yield 'no address' => ['localhost', false];
    }

    #[Test]
    #[DataProvider('addresses')]
    public function onlyPublicAddressesAreFetched(string $address, bool $public): void
    {
        self::assertSame($public, GuzzleClientMetadataDocumentFetcher::isPublicAddress($address));
    }

    #[Test]
    public function theFetcherRefusesPrivateAddressesWithoutConnecting(): void
    {
        $fetcher = new GuzzleClientMetadataDocumentFetcher();
        foreach (['https://127.0.0.1/metadata.json', 'https://[::1]/metadata.json', 'https://169.254.169.254/latest/meta-data', 'http://93.184.215.14/metadata.json'] as $url) {
            try {
                $fetcher->fetch($url);
                self::fail(sprintf('%s was fetched', $url));
            } catch (ClientMetadataDocumentNotFetched $exception) {
                self::assertFalse($exception->isTemporary(), $url);
            }
        }
    }

    #[Test]
    public function maxAgeIsReadFromCacheControl(): void
    {
        self::assertSame(600, FetchedDocument::maxAgeOf('public, max-age=600'));
        self::assertSame(0, FetchedDocument::maxAgeOf('no-store'));
        self::assertNull(FetchedDocument::maxAgeOf('public'));
    }

    /**
     * @param array<string, mixed> $overrides null removes a field
     * @return array<string, mixed>
     */
    private static function document(array $overrides = []): array
    {
        return array_filter($overrides + [
            'client_id' => self::CLIENT_ID,
            'client_name' => 'Example MCP client',
            'redirect_uris' => [self::REDIRECT_URI, 'http://127.0.0.1/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ], static fn ($value) => $value !== null);
    }

    private function problemWith(string $clientId): string
    {
        try {
            $this->objectManager->get(ClientMetadataDocuments::class)->find($clientId);
        } catch (InvalidClientMetadataDocument $exception) {
            return $exception->getMessage();
        }
        self::fail('The client was found');
    }

    /**
     * Makes the cached document outdated
     */
    private function expire(): void
    {
        $cache = $this->objectManager->get(CacheManager::class)->getCache('Neos_OAuth_ClientMetadataDocuments');
        $entry = $cache->get(sha1(self::CLIENT_ID));
        $entry['freshUntil'] = time() - 1;
        $cache->set(sha1(self::CLIENT_ID), $entry);
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
    }

    /**
     * Validates the authorization request and issues a code as the AuthorizeController does once the user approved,
     * without the login and consent pages
     *
     * @param list<string> $audience
     */
    private function authorizationCode(string $redirectUri, array $audience): string
    {
        $authorizationServer = $this->objectManager->get(ServerFactory::class)->getAuthorizationServer();
        $authorizationRequest = $authorizationServer->validateAuthorizationRequest($this->authorizationRequest(self::CLIENT_ID, $redirectUri));
        $authorizationRequest->setUser(new UserEntity('editor'));
        $authorizationRequest->setAuthorizationApproved(true);

        $response = $this->objectManager->get(TokenRecords::class)->withAudience($audience, fn () => $authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response()));
        parse_str((string)parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        self::assertStringStartsWith($redirectUri . '?', $response->getHeaderLine('Location'));
        self::assertIsString($query['code'] ?? null, $response->getHeaderLine('Location'));
        return $query['code'];
    }

    private function authorizationRequest(string $clientId, string $redirectUri): ServerRequest
    {
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => 'neos.oauth.test',
            'state' => 'xyz',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];
        return (new ServerRequest('GET', 'http://localhost/oauth/authorize?' . http_build_query($query)))->withQueryParams($query);
    }

    /**
     * The error the AuthorizeController renders or redirects for the request
     */
    private function authorizationError(string $clientId, string $redirectUri): OAuthServerException
    {
        $controller = $this->objectManager->get(AuthorizeController::class);
        $validate = new \ReflectionMethod($controller, 'validate');
        try {
            $validate->invoke($controller, $this->authorizationRequest($clientId, $redirectUri));
        } catch (OAuthServerException $exception) {
            return $exception;
        }
        self::fail('The authorization request is valid');
    }

    /**
     * @param array<string, string> $parameters
     * @return array{status: int, body: array<string, mixed>}
     */
    private function tokenRequest(array $parameters): array
    {
        $response = $this->browser->sendRequest(new ServerRequest('POST', 'http://localhost/oauth/token', ['Content-Type' => 'application/x-www-form-urlencoded'], http_build_query($parameters)));
        return ['status' => $response->getStatusCode(), 'body' => json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)];
    }

    private function authenticates(string $bearer, string $resource): bool
    {
        // the browser runs all requests in one process: forget the previous request's authentication
        $this->inject($this->objectManager->get(AuthenticationManagerInterface::class), 'isAuthenticated', null);
        foreach ($this->objectManager->get(TokenAndProviderFactoryInterface::class)->getTokens() as $token) {
            if ($token instanceof BearerToken) {
                $this->inject($token, 'credentials', ['bearer' => '']);
            }
        }
        $this->objectManager->get(ClientMetadataDocuments::class)->reset();
        $response = $this->browser->sendRequest(new ServerRequest('GET', $resource . '/whoami', ['Authorization' => 'Bearer ' . $bearer]));
        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        return json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)['authenticated'];
    }

    /**
     * @return array<string, mixed>
     */
    private function discoveryDocument(): array
    {
        return json_decode((string)$this->browser->request('http://localhost/.well-known/oauth-authorization-server')->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function enable(bool $enabled): void
    {
        $this->inject($this->objectManager->get(AuthorizationServerMetadata::class), 'clientIdMetadataDocuments', $enabled);
    }
}
