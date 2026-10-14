<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\ScopeProvider;
use Neos\OAuth\Domain\ScopeRegistry;

/**
 * The resources that accept the tokens, as configured in Neos.OAuth.protectedResources, and their metadata
 * documents (RFC 9728)
 *
 * A resource is identified by its URI, <issuer>/<path>. Clients name it in the "resource" parameter (RFC 8707) to get a
 * token bound to it: the token's audience. Such a token is only accepted by that resource
 */
#[Flow\Scope('singleton')]
final class ProtectedResources
{
    public const string METADATA_PATH = '/.well-known/oauth-protected-resource';

    /**
     * @var array<string, array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool}|null>
     */
    #[Flow\InjectConfiguration(path: 'protectedResources', package: 'Neos.OAuth')]
    protected array $resources = [];

    public function __construct(
        private readonly AuthorizationServerMetadata $authorizationServer,
        private readonly ScopeRegistry $scopeRegistry,
    ) {
    }

    /**
     * @return array<string, array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool}> by key
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
                'resource' => $this->uriOf($resource),
                'authorization_servers' => [$issuer],
                'scopes_supported' => $this->scopesOf($resource),
                'bearer_methods_supported' => ['header'],
                'resource_name' => $resource['name'] ?? null,
                'resource_documentation' => isset($resource['documentation']) ? $issuer . '/' . ltrim($resource['documentation'], '/') : null,
            ], static fn ($value) => $value !== null);
        }
        return null;
    }

    /**
     * The audience of a token requested with the given resource indicators (RFC 8707): their canonical URIs
     *
     * @param list<string> $indicators the values of the request's "resource" parameters, see {@see self::indicatorsIn()}
     * @return list<string> the URIs of the resources, empty if none were requested (the token isn't bound)
     * @throws InvalidTarget if one of them is no protected resource
     * @throws IssuerNotConfigured
     */
    public function audienceFor(array $indicators): array
    {
        if ($indicators === []) {
            return [];
        }
        $uris = array_map($this->uriOf(...), $this->all());
        $audience = [];
        foreach ($indicators as $indicator) {
            // the canonical URI has no trailing slash (RFC 8707 section 2), clients may still send one
            $uri = rtrim($indicator, '/');
            if (!in_array($uri, $uris, true)) {
                throw new InvalidTarget(sprintf('"%s" is no protected resource of this server', $indicator), 1792000001);
            }
            $audience[] = $uri;
        }
        return array_values(array_unique($audience));
    }

    /**
     * Whether a token with the given audience may be used for a request to the given path
     *
     * The path belongs to the resource with the longest matching path. A token bound to resources is only accepted by
     * those, an unbound one by every resource that doesn't set requireAudience
     *
     * @param string $path the request's path relative to the base URI
     * @param list<string> $audience the URIs of the resources the token was issued for, empty if it isn't bound
     */
    public function accepts(string $path, array $audience): bool
    {
        $resource = $this->resourceForPath($path);
        if ($audience === []) {
            return !($resource['requireAudience'] ?? false);
        }
        try {
            return $resource !== null && in_array($this->uriOf($resource), $audience, true);
        } catch (IssuerNotConfigured) {
            return false;
        }
    }

    /**
     * The values of the "resource" parameters in a query string or form body
     *
     * RFC 8707 repeats the parameter for several resources, which PHP's parse_str() would reduce to the last one
     *
     * @return list<string>
     */
    public static function indicatorsIn(string $urlEncodedParameters): array
    {
        $indicators = [];
        foreach (explode('&', $urlEncodedParameters) as $pair) {
            [$name, $value] = array_map('urldecode', explode('=', $pair, 2) + [1 => '']);
            if ($name === 'resource' && $value !== '') {
                $indicators[] = $value;
            }
        }
        return $indicators;
    }

    /**
     * The scopes the resource accepts: those of its scopeProvider, or the listed ones
     *
     * @param array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool} $resource
     * @return list<string>|null
     */
    private function scopesOf(array $resource): ?array
    {
        if (isset($resource['scopeProvider'])) {
            return array_keys($this->scopeRegistry->provider($resource['scopeProvider'])->scopes());
        }
        return $resource['scopes'] ?? null;
    }

    /**
     * @param array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool} $resource
     * @throws IssuerNotConfigured
     */
    private function uriOf(array $resource): string
    {
        return $this->authorizationServer->issuer() . '/' . trim($resource['path'], '/');
    }

    /**
     * @return array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool}|null
     */
    private function resourceForPath(string $path): ?array
    {
        $path = trim($path, '/');
        $match = null;
        foreach ($this->all() as $resource) {
            $resourcePath = trim($resource['path'], '/');
            $matches = $path === $resourcePath || str_starts_with($path, $resourcePath . '/');
            if ($matches && ($match === null || strlen($resourcePath) > strlen(trim($match['path'], '/')))) {
                $match = $resource;
            }
        }
        return $match;
    }

    /**
     * @return array{path: string, name?: string, scopes?: list<string>, scopeProvider?: class-string<ScopeProvider>, documentation?: string, requireAudience?: bool}
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
