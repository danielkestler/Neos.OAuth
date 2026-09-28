<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;

/**
 * The resources that accept the tokens, as configured in Neos.OAuth.protectedResources, and their metadata
 * documents (RFC 9728)
 */
#[Flow\Scope('singleton')]
final class ProtectedResources
{
    public const string METADATA_PATH = '/.well-known/oauth-protected-resource';

    /**
     * @var array<string, array{path: string, name?: string, scopes?: list<string>, documentation?: string}|null>
     */
    #[Flow\InjectConfiguration(path: 'protectedResources', package: 'Neos.OAuth')]
    protected array $resources = [];

    public function __construct(
        private readonly AuthorizationServerMetadata $authorizationServer,
    ) {
    }

    /**
     * @return array<string, array{path: string, name?: string, scopes?: list<string>, documentation?: string}> by key
     */
    public function all(): array
    {
        return array_filter($this->resources, static fn ($resource) => $resource !== null);
    }

    /**
     * The absolute URL of a resource's metadata document, e.g. for the "resource_metadata" of a 401 challenge
     *
     * @param string $key the key the resource is configured with, usually the package key
     * @throws IssuerNotConfigured
     */
    public function metadataUrl(string $key): string
    {
        return $this->authorizationServer->issuer() . self::METADATA_PATH . '/' . $this->resource($key)['path'];
    }

    /**
     * The metadata document of the resource with the given path, null if there is none
     *
     * @return array<string, mixed>|null
     * @throws IssuerNotConfigured
     */
    public function documentForPath(string $path): ?array
    {
        foreach ($this->resources as $resource) {
            if ($resource === null || trim($resource['path'], '/') !== trim($path, '/')) {
                continue;
            }
            $issuer = $this->authorizationServer->issuer();
            return array_filter([
                'resource' => $issuer . '/' . trim($resource['path'], '/'),
                'authorization_servers' => [$issuer],
                'scopes_supported' => $resource['scopes'] ?? null,
                'bearer_methods_supported' => ['header'],
                'resource_name' => $resource['name'] ?? null,
                'resource_documentation' => isset($resource['documentation']) ? $issuer . '/' . ltrim($resource['documentation'], '/') : null,
            ], static fn ($value) => $value !== null);
        }
        return null;
    }

    /**
     * @return array{path: string, name?: string, scopes?: list<string>, documentation?: string}
     */
    private function resource(string $key): array
    {
        $resource = $this->resources[$key] ?? null;
        if ($resource === null || !isset($resource['path'])) {
            throw new \InvalidArgumentException(sprintf('There is no protected resource "%s" in Neos.OAuth.protectedResources', $key), 1790100051);
        }
        return $resource;
    }
}
