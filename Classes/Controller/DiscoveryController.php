<?php
declare(strict_types=1);

namespace Neos\OAuth\Controller;

use GuzzleHttp\Psr7\Response;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Neos\OAuth\Security\IssuerNotConfigured;
use Neos\OAuth\Security\ProtectedResources;
use Psr\Http\Message\ResponseInterface;

/**
 * The discovery documents: authorization server metadata (RFC 8414) and protected resource metadata (RFC 9728)
 */
class DiscoveryController extends ActionController
{
    #[Flow\Inject]
    protected AuthorizationServerMetadata $authorizationServer;

    #[Flow\Inject]
    protected ProtectedResources $protectedResources;

    public function authorizationServerAction(): ResponseInterface
    {
        try {
            return self::json(200, $this->authorizationServer->document());
        } catch (IssuerNotConfigured $exception) {
            return $this->issuerNotConfigured($exception);
        }
    }

    public function protectedResourceAction(string $resourcePath): ResponseInterface
    {
        try {
            $document = $this->protectedResources->documentForPath($resourcePath);
        } catch (IssuerNotConfigured $exception) {
            return $this->issuerNotConfigured($exception);
        }
        return $document !== null
            ? self::json(200, $document)
            : self::json(404, ['error' => 'not_found', 'error_description' => sprintf('There is no protected resource "%s"', $resourcePath)]);
    }

    private function issuerNotConfigured(IssuerNotConfigured $exception): ResponseInterface
    {
        $this->logger->error($exception->getMessage());
        return self::json(500, ['error' => 'server_error', 'error_description' => 'The authorization server is not configured, run ./flow oauth:status']);
    }

    /**
     * Public documents: any origin may read them, e.g. browser based clients
     *
     * @param array<string, mixed> $body
     */
    private static function json(int $status, array $body): ResponseInterface
    {
        return new Response($status, [
            'Content-Type' => 'application/json',
            'Access-Control-Allow-Origin' => '*',
            'Cache-Control' => $status === 200 ? 'public, max-age=3600' : 'no-store',
        ], json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }
}
