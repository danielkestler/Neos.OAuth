<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Controller;

use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;

class RegistrationControllerTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    public function setUp(): void
    {
        parent::setUp();
        $this->enableRegistration(true);
    }

    public function tearDown(): void
    {
        $this->enableRegistration(false);
        parent::tearDown();
    }

    #[Test]
    public function registersPublicClients(): void
    {
        $response = $this->register(['client_name' => 'MCP client', 'redirect_uris' => ['http://127.0.0.1:3334/callback'], 'scope' => 'neos.oauth.test']);

        self::assertSame(201, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('MCP client', $body['client_name']);
        self::assertSame(['authorization_code', 'refresh_token'], $body['grant_types']);
        self::assertSame('none', $body['token_endpoint_auth_method']);
        self::assertSame('neos.oauth.test', $body['scope']);

        $client = $this->objectManager->get(OAuthClientRepository::class)->findOneByClientIdentifier($body['client_id']);
        self::assertNotNull($client);
        self::assertFalse($client->isConfidential());
        self::assertFalse($client->isFirstParty());
        self::assertNull($client->getAccountIdentifier());
        self::assertSame(['http://127.0.0.1:3334/callback'], $client->getRedirectUris());
        self::assertSame(['neos.oauth.test'], $client->getScopes());
    }

    #[Test]
    public function clientsWithoutScopeGetAllScopes(): void
    {
        $body = json_decode((string)$this->register(['redirect_uris' => ['https://example.com/callback']])->getBody(), true, flags: JSON_THROW_ON_ERROR);

        self::assertContains('neos.oauth.test', explode(' ', $body['scope']));
        self::assertContains('neos.oauth.provided', explode(' ', $body['scope']));
        self::assertSame('Dynamically registered client', $body['client_name']);
    }

    /**
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function invalidRegistrations(): iterable
    {
        yield 'no object' => [['https://example.com/callback'], 'invalid_client_metadata'];
        yield 'no redirect URIs' => [['client_name' => 'x'], 'invalid_redirect_uri'];
        yield 'http redirect URI' => [['redirect_uris' => ['http://example.com/callback']], 'invalid_redirect_uri'];
        yield 'confidential' => [['redirect_uris' => ['https://example.com/callback'], 'token_endpoint_auth_method' => 'client_secret_basic'], 'invalid_client_metadata'];
        yield 'client credentials' => [['redirect_uris' => ['https://example.com/callback'], 'grant_types' => ['authorization_code', 'client_credentials']], 'invalid_client_metadata'];
        yield 'implicit' => [['redirect_uris' => ['https://example.com/callback'], 'response_types' => ['token']], 'invalid_client_metadata'];
        yield 'unknown scope' => [['redirect_uris' => ['https://example.com/callback'], 'scope' => 'neos.oauth.test unknown'], 'invalid_client_metadata'];
    }

    #[Test]
    #[DataProvider('invalidRegistrations')]
    public function rejectsInvalidMetadata(mixed $metadata, string $error): void
    {
        $response = $this->register($metadata);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame($error, json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)['error']);
        self::assertSame(0, $this->objectManager->get(OAuthClientRepository::class)->countAll());
    }

    #[Test]
    public function isDisabledByDefault(): void
    {
        $this->enableRegistration(false);

        $response = $this->register(['redirect_uris' => ['https://example.com/callback']]);

        self::assertSame(403, $response->getStatusCode());
        $document = json_decode((string)$this->browser->request('http://localhost/.well-known/oauth-authorization-server')->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertArrayNotHasKey('registration_endpoint', $document);
    }

    #[Test]
    public function theDiscoveryDocumentNamesTheEndpointWhenEnabled(): void
    {
        $document = json_decode((string)$this->browser->request('http://localhost/.well-known/oauth-authorization-server')->getBody(), true, flags: JSON_THROW_ON_ERROR);

        self::assertSame('http://localhost/oauth/register', $document['registration_endpoint']);
    }

    private function register(mixed $metadata): ResponseInterface
    {
        return $this->browser->sendRequest(
            (new ServerRequest('POST', 'http://localhost/oauth/register', ['Content-Type' => 'application/json']))
                ->withBody(Utils::streamFor(json_encode($metadata, JSON_THROW_ON_ERROR)))
        );
    }

    private function enableRegistration(bool $enabled): void
    {
        $this->inject($this->objectManager->get(AuthorizationServerMetadata::class), 'dynamicClientRegistration', $enabled);
    }
}
