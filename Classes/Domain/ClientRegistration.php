<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\AccountRepository;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;

/**
 * Registers clients in the database, for the CLI and packages that set up clients of their own
 */
#[Flow\Scope('singleton')]
final class ClientRegistration
{
    #[Flow\InjectConfiguration(path: 'accountAuthenticationProviderName', package: 'Neos.OAuth')]
    protected string $accountAuthenticationProviderName;

    #[Flow\Inject]
    protected ClientDirectory $clientDirectory;

    public function __construct(
        private readonly OAuthClientRepository $clientRepository,
        private readonly ScopeRegistry $scopeRegistry,
        private readonly AccountRepository $accountRepository,
        private readonly PersistenceManagerInterface $persistenceManager,
    ) {
    }

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string>|null $scopes null for all registered scopes
     * @return string|null the client secret of a confidential client, which is not stored and cannot be retrieved later
     * @throws \InvalidArgumentException if the client cannot be registered like this
     */
    public function register(
        string $identifier,
        string $name,
        array $redirectUris,
        array $grantTypes,
        ?array $scopes,
        bool $confidential,
        bool $firstParty,
        ?string $accountIdentifier,
    ): ?string {
        if ($this->clientRepository->findOneByClientIdentifier($identifier) !== null || $this->clientDirectory->isDeclared($identifier)) {
            throw new \InvalidArgumentException(sprintf('A client "%s" exists already', $identifier), 1790100040);
        }
        foreach ($redirectUris as $redirectUri) {
            self::assertAcceptableRedirectUri($redirectUri);
        }
        $knownScopes = $this->scopeRegistry->identifiers();
        $scopes ??= $knownScopes;
        $unknownScopes = array_diff($scopes, $knownScopes);
        if ($unknownScopes !== []) {
            throw new \InvalidArgumentException(sprintf('Unknown scopes: %s. Registered are: %s', implode(', ', $unknownScopes), implode(', ', $knownScopes) ?: '(none)'), 1790100041);
        }
        if ($accountIdentifier !== null && $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($accountIdentifier, $this->accountAuthenticationProviderName) === null) {
            throw new \InvalidArgumentException(sprintf('There is no active account "%s" of the provider "%s"', $accountIdentifier, $this->accountAuthenticationProviderName), 1790100042);
        }

        $secret = $confidential ? bin2hex(random_bytes(32)) : null;
        $this->clientRepository->add(new OAuthClient(
            $identifier,
            $name,
            $secret !== null ? password_hash($secret, PASSWORD_DEFAULT) : null,
            array_values($redirectUris),
            array_values($grantTypes),
            array_values($scopes),
            $firstParty,
            $accountIdentifier,
        ));
        $this->persistenceManager->persistAll();
        return $secret;
    }

    /**
     * https, http on a loopback address, or the custom scheme of a native app, without a fragment (RFC 6749 3.1.2)
     *
     * @throws \InvalidArgumentException
     */
    public static function assertAcceptableRedirectUri(string $uri): void
    {
        $parts = parse_url($uri);
        $acceptable = $parts !== false && isset($parts['scheme']) && !isset($parts['fragment']) && match (strtolower($parts['scheme'])) {
            'https' => isset($parts['host']),
            'http' => in_array($parts['host'] ?? '', ['localhost', '127.0.0.1', '[::1]'], true),
            'javascript', 'data', 'file', 'vbscript' => false,
            default => true,
        };
        if (!$acceptable) {
            throw new \InvalidArgumentException(sprintf('Invalid redirect URI "%s": use https, http on a loopback address, or a custom scheme of a native app', $uri), 1790100044);
        }
    }
}
