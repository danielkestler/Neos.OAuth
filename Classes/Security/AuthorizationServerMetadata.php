<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;
use Neos\Neos\Domain\Repository\SiteRepository;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\ScopeRegistry;

/**
 * Where the endpoints of the authorization server are and what they support: for the discovery document (RFC 8414)
 * and for packages that describe them, e.g. in an OpenAPI document
 *
 * The paths are those of Routes.yaml (verified by AuthorizationServerMetadataTest). They are not resolved with the
 * router: consumers call this while their own routes are being built, e.g. the OpenAPI adapter
 */
#[Flow\Scope('singleton')]
final class AuthorizationServerMetadata
{
    public const string TOKEN_PATH = '/oauth/token';

    public const string AUTHORIZATION_PATH = '/oauth/authorize';

    public const string DISCOVERY_PATH = '/.well-known/oauth-authorization-server';

    #[Flow\InjectConfiguration(path: 'issuer', package: 'Neos.OAuth')]
    protected ?string $issuer = null;

    #[Flow\InjectConfiguration(path: 'http.baseUri', package: 'Neos.Flow')]
    protected ?string $baseUri = null;

    private ?string $resolvedIssuer = null;

    private ?string $issuerSource = null;

    public function __construct(
        private readonly ScopeRegistry $scopeRegistry,
        private readonly SiteRepository $siteRepository,
    ) {
    }

    public function tokenUrl(): string
    {
        return self::TOKEN_PATH;
    }

    public function authorizationUrl(): string
    {
        return self::AUTHORIZATION_PATH;
    }

    /**
     * PKCE is required from every client of the authorization code grant, with one of these methods
     *
     * @return list<string>
     */
    public function codeChallengeMethods(): array
    {
        return ['S256'];
    }

    /**
     * The absolute base URI of the authorization server, without trailing slash: from Neos.OAuth.issuer,
     * Neos.Flow.http.baseUri or the primary domain of the default site, in that order
     *
     * @throws IssuerNotConfigured
     */
    public function issuer(): string
    {
        if ($this->resolvedIssuer === null) {
            [$this->resolvedIssuer, $this->issuerSource] = $this->resolveIssuer();
        }
        return $this->resolvedIssuer;
    }

    /**
     * Where the issuer comes from, e.g. for ./flow oauth:status
     *
     * @throws IssuerNotConfigured
     */
    public function issuerSource(): string
    {
        $this->issuer();
        return (string)$this->issuerSource;
    }

    /**
     * @return array{string, string} the issuer and where it comes from
     */
    private function resolveIssuer(): array
    {
        if ($this->issuer) {
            return [rtrim($this->issuer, '/'), 'Neos.OAuth.issuer'];
        }
        if ($this->baseUri) {
            return [rtrim($this->baseUri, '/'), 'Neos.Flow.http.baseUri'];
        }
        // configured by the editors, not taken from the request
        $domain = $this->siteRepository->findDefault()?->getPrimaryDomain();
        if ($domain !== null) {
            $port = $domain->getPort();
            return [
                sprintf('%s://%s%s', $domain->getScheme() ?: 'https', $domain->getHostname(), $port !== null ? ':' . $port : ''),
                sprintf('the primary domain of the site "%s"', $domain->getSite()->getNodeName()->value),
            ];
        }
        throw new IssuerNotConfigured('Configure the absolute base URI of the authorization server in Neos.OAuth.issuer, or add a domain to the default site', 1790100050);
    }

    /**
     * The authorization server metadata document (RFC 8414)
     *
     * @return array<string, mixed>
     * @throws IssuerNotConfigured
     */
    public function document(): array
    {
        $issuer = $this->issuer();
        return [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . self::AUTHORIZATION_PATH,
            'token_endpoint' => $issuer . self::TOKEN_PATH,
            'scopes_supported' => $this->scopeRegistry->identifiers(),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => OAuthClient::SUPPORTED_GRANTS,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'code_challenge_methods_supported' => $this->codeChallengeMethods(),
        ];
    }
}
