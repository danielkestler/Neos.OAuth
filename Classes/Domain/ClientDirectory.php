<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Neos\OAuth\Security\IssuerNotConfigured;
use Psr\Log\LoggerInterface;

/**
 * All clients: those declared in Neos.OAuth.clients and those registered in the database
 *
 * Declared clients are public (no secret) and need no setup: "{issuer}" in their redirect URIs is replaced with the
 * issuer of the environment
 */
#[Flow\Scope('singleton')]
final class ClientDirectory
{
    /**
     * @var array<string, array{name?: string, redirectUris?: list<string>, grantTypes?: list<string>, scopes?: list<string>, firstParty?: bool}|null>
     */
    #[Flow\InjectConfiguration(path: 'clients', package: 'Neos.OAuth')]
    protected array $clientConfiguration = [];

    /**
     * @var array<string, OAuthClient>
     */
    private array $declaredClients = [];

    public function __construct(
        private readonly OAuthClientRepository $clientRepository,
        private readonly ScopeRegistry $scopeRegistry,
        private readonly AuthorizationServerMetadata $authorizationServer,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function find(string $identifier): ?OAuthClient
    {
        if ($this->isDeclared($identifier)) {
            try {
                return $this->declared($identifier);
            } catch (\InvalidArgumentException | IssuerNotConfigured $exception) {
                $this->logger->error(sprintf('The client "%s" in Neos.OAuth.clients is not usable: %s', $identifier, $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
                return null;
            }
        }
        return $this->clientRepository->findOneByClientIdentifier($identifier);
    }

    public function isDeclared(string $identifier): bool
    {
        return ($this->clientConfiguration[$identifier] ?? null) !== null;
    }

    /**
     * @return list<string>
     */
    public function declaredIdentifiers(): array
    {
        return array_keys(array_filter($this->clientConfiguration, static fn ($configuration) => $configuration !== null));
    }

    /**
     * The declared client, built from its configuration
     *
     * @throws \InvalidArgumentException|IssuerNotConfigured if the configuration is invalid or the issuer is unknown
     */
    public function declared(string $identifier): OAuthClient
    {
        if (isset($this->declaredClients[$identifier])) {
            return $this->declaredClients[$identifier];
        }
        $configuration = $this->clientConfiguration[$identifier] ?? null;
        if ($configuration === null) {
            throw new \InvalidArgumentException(sprintf('There is no client "%s" in Neos.OAuth.clients', $identifier), 1790100060);
        }
        $grantTypes = $configuration['grantTypes'] ?? [OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN];
        if (in_array(OAuthClient::GRANT_CLIENT_CREDENTIALS, $grantTypes, true)) {
            throw new \InvalidArgumentException('Declared clients are public and cannot use the client_credentials grant, register a confidential client with ./flow oauth:createclient', 1790100061);
        }
        $redirectUris = [];
        foreach ($configuration['redirectUris'] ?? [] as $redirectUri) {
            $redirectUri = str_contains($redirectUri, '{issuer}') ? str_replace('{issuer}', $this->authorizationServer->issuer(), $redirectUri) : $redirectUri;
            ClientRegistration::assertAcceptableRedirectUri($redirectUri);
            $redirectUris[] = $redirectUri;
        }
        $scopes = $configuration['scopes'] ?? $this->scopeRegistry->identifiers();
        $unknownScopes = array_diff($scopes, $this->scopeRegistry->identifiers());
        if ($unknownScopes !== []) {
            throw new \InvalidArgumentException(sprintf('Unknown scopes: %s', implode(', ', $unknownScopes)), 1790100062);
        }
        return $this->declaredClients[$identifier] = new OAuthClient(
            $identifier,
            $configuration['name'] ?? $identifier,
            null,
            $redirectUris,
            array_values($grantTypes),
            array_values($scopes),
            (bool)($configuration['firstParty'] ?? false),
            null,
        );
    }
}
