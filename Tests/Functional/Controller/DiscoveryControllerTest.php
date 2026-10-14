<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Controller;

use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Tests\FunctionalTestCase;
use PHPUnit\Framework\Attributes\Test;

class DiscoveryControllerTest extends FunctionalTestCase
{
    #[Test]
    public function servesTheAuthorizationServerMetadata(): void
    {
        $response = $this->browser->request('http://localhost/.well-known/oauth-authorization-server');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $document = json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('http://localhost', $document['issuer']);
        self::assertSame('http://localhost/oauth/authorize', $document['authorization_endpoint']);
        self::assertSame('http://localhost/oauth/token', $document['token_endpoint']);
        self::assertContains('neos.oauth.test', $document['scopes_supported']);
        self::assertContains('neos.oauth.provided', $document['scopes_supported']);
        self::assertSame(['S256'], $document['code_challenge_methods_supported']);
    }

    #[Test]
    public function servesTheMetadataOfProtectedResources(): void
    {
        $response = $this->browser->request('http://localhost/.well-known/oauth-protected-resource/test-resource');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([
            'resource' => 'http://localhost/test-resource',
            'authorization_servers' => ['http://localhost'],
            'scopes_supported' => ['neos.oauth.test'],
            'bearer_methods_supported' => ['header'],
            'resource_name' => 'Test resource',
        ], json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR));

        self::assertSame(404, $this->browser->request('http://localhost/.well-known/oauth-protected-resource/unknown')->getStatusCode());
    }

    #[Test]
    public function protectedResourcesCanTakeTheirScopesFromAScopeProvider(): void
    {
        $response = $this->browser->request('http://localhost/.well-known/oauth-protected-resource/provided-resource');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['neos.oauth.provided'], json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)['scopes_supported']);
    }

    /**
     * As MCP clients like Claude Code send it: Flow's content negotiation must not answer it with a 406
     */
    #[Test]
    public function theJsonEndpointsAcceptRequestsForJson(): void
    {
        foreach (['GET /.well-known/oauth-authorization-server' => 200, 'GET /.well-known/oauth-protected-resource/test-resource' => 200, 'POST /oauth/token' => 400, 'POST /oauth/register' => 403] as $request => $status) {
            [$method, $path] = explode(' ', $request);
            $response = $this->browser->sendRequest(new ServerRequest($method, 'http://localhost' . $path, ['Accept' => 'application/json']));

            self::assertSame($status, $response->getStatusCode(), $request);
            self::assertStringStartsWith('application/json', $response->getHeaderLine('Content-Type'), $request);
        }
    }
}
