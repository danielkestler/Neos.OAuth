<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Cache\Frontend\VariableFrontend;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Infrastructure\Http\ClientMetadataDocumentFetcher;
use Neos\OAuth\Infrastructure\Http\ClientMetadataDocumentNotFetched;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Psr\Log\LoggerInterface;

/**
 * Clients identified by the URL of their metadata document (OAuth Client ID Metadata Document), e.g. MCP clients
 *
 * Instead of registering, the client uses an https URL as client_id, and the document at that URL describes it. Such
 * clients are treated like dynamically registered ones: public (PKCE, no secret), never first party, no account of
 * their own. Nobody vouches for them, so the consent page shows the host of the URL along with the client's name.
 *
 * Documents are cached as long as their Cache-Control allows, within the configured bounds, because clients are looked
 * up on every request with a token. When a cached document is outdated and cannot be fetched for a temporary reason
 * (network, timeout, server error), the outdated one is used for the grace period, so an outage of the client's
 * website doesn't lock out its users. A definite answer (e.g. 404 or an invalid document) ends the client at once
 */
#[Flow\Scope('singleton')]
final class ClientMetadataDocuments
{
    /**
     * The client_id column of TokenRecord
     */
    private const int MAXIMUM_LENGTH = 255;

    private const array GRANT_TYPES = [OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN];

    /**
     * @var array{maximumSize?: int, cacheLifetime?: array{minimum?: int, maximum?: int}, failureCacheLifetime?: int, gracePeriod?: int}
     */
    #[Flow\InjectConfiguration(path: 'clientIdMetadataDocuments', package: 'Neos.OAuth')]
    protected array $settings = [];

    /**
     * Set in Objects.yaml
     */
    protected VariableFrontend $cache;

    /**
     * The clients and failures of this request, by client ID: league looks up a client several times
     *
     * @var array<string, OAuthClient|InvalidClientMetadataDocument>
     */
    private array $resolved = [];

    public function __construct(
        private readonly ClientMetadataDocumentFetcher $fetcher,
        private readonly ScopeRegistry $scopeRegistry,
        private readonly AuthorizationServerMetadata $authorizationServer,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Whether the client ID is meant as the URL of a metadata document, as opposed to an identifier of a declared or
     * registered client. It need not be a valid one
     */
    public static function isUrl(string $clientId): bool
    {
        return str_contains($clientId, '://');
    }

    public function isEnabled(): bool
    {
        return $this->authorizationServer->clientIdMetadataDocumentsSupported();
    }

    /**
     * The client described by the metadata document at the URL
     *
     * @throws InvalidClientMetadataDocument
     */
    public function find(string $clientId): OAuthClient
    {
        $resolved = $this->resolved[$clientId] ??= $this->resolve($clientId);
        if ($resolved instanceof InvalidClientMetadataDocument) {
            throw $resolved;
        }
        return $resolved;
    }

    /**
     * Forgets what was fetched in this request, e.g. for tests
     */
    public function reset(): void
    {
        $this->resolved = [];
    }

    private function resolve(string $clientId): OAuthClient|InvalidClientMetadataDocument
    {
        if (!$this->isEnabled()) {
            return new InvalidClientMetadataDocument('This server does not support client ID metadata documents, register the client instead', 1792100100);
        }
        try {
            self::assertValidUrl($clientId);
        } catch (InvalidClientMetadataDocument $exception) {
            return $exception;
        }

        $cacheIdentifier = sha1($clientId);
        $now = time();
        $entry = $this->cache->get($cacheIdentifier);
        if (is_array($entry) && isset($entry['error'])) {
            return new InvalidClientMetadataDocument($entry['error'], 1792100101);
        }
        if (is_array($entry) && ($entry['freshUntil'] > $now || $entry['retryAt'] > $now)) {
            return $this->client($clientId, $entry['metadata']);
        }

        try {
            $document = $this->fetcher->fetch($clientId);
            // the fetcher aborts larger responses early, this holds for every fetcher
            $maximumSize = (int)($this->settings['maximumSize'] ?? 65536);
            if (strlen($document->body) > $maximumSize) {
                throw new ClientMetadataDocumentNotFetched(sprintf('The document is larger than %d bytes', $maximumSize), 1792100104);
            }
            $metadata = self::validate($clientId, $document->body);
        } catch (ClientMetadataDocumentNotFetched $exception) {
            if ($exception->isTemporary() && is_array($entry)) {
                // keep the outdated document, but don't try again on every request
                $this->logger->warning(sprintf('Using the outdated metadata document of the client "%s", it cannot be fetched: %s', $clientId, $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__));
                $entry['retryAt'] = $now + $this->failureCacheLifetime();
                $this->cache->set($cacheIdentifier, $entry, [], max(1, min($entry['staleUntil'], $entry['retryAt']) - $now));
                return $this->client($clientId, $entry['metadata']);
            }
            return $this->failed($cacheIdentifier, sprintf('The client metadata document at %s cannot be fetched: %s', $clientId, $exception->getMessage()));
        } catch (InvalidClientMetadataDocument $exception) {
            return $this->failed($cacheIdentifier, sprintf('The client metadata document at %s is invalid: %s', $clientId, $exception->getMessage()));
        }

        $minimum = (int)($this->settings['cacheLifetime']['minimum'] ?? 300);
        $maximum = (int)($this->settings['cacheLifetime']['maximum'] ?? 86400);
        $freshUntil = $now + max($minimum, min($maximum, $document->maxAge ?? $minimum));
        $staleUntil = $freshUntil + max(0, (int)($this->settings['gracePeriod'] ?? 0));
        $this->cache->set($cacheIdentifier, ['metadata' => $metadata, 'freshUntil' => $freshUntil, 'staleUntil' => $staleUntil, 'retryAt' => 0], [], max(1, $staleUntil - $now));
        return $this->client($clientId, $metadata);
    }

    private function failed(string $cacheIdentifier, string $message): InvalidClientMetadataDocument
    {
        $this->logger->info($message, LogEnvironment::fromMethodName(__METHOD__));
        // not for long: the developer may be fixing the document right now
        $this->cache->set($cacheIdentifier, ['error' => $message], [], $this->failureCacheLifetime());
        return new InvalidClientMetadataDocument($message, 1792100102);
    }

    private function failureCacheLifetime(): int
    {
        // 0 would mean forever to the cache
        return max(1, (int)($this->settings['failureCacheLifetime'] ?? 30));
    }

    /**
     * @param array{name: string, redirectUris: list<string>, grantTypes: list<string>, scope: string|null} $metadata
     */
    private function client(string $clientId, array $metadata): OAuthClient
    {
        // registered scopes may change, so they are applied on each use
        $scopes = $this->scopeRegistry->identifiers();
        if ($metadata['scope'] !== null) {
            $scopes = array_values(array_intersect($scopes, explode(' ', $metadata['scope'])));
        }
        return new OAuthClient($clientId, $metadata['name'], null, $metadata['redirectUris'], $metadata['grantTypes'], $scopes, false, null);
    }

    /**
     * An https URL with a path, without fragment, credentials or dot segments, that fits into the database
     *
     * @throws InvalidClientMetadataDocument
     */
    public static function assertValidUrl(string $clientId): void
    {
        $parts = parse_url($clientId);
        $problem = match (true) {
            strlen($clientId) > self::MAXIMUM_LENGTH => sprintf('it is longer than %d characters', self::MAXIMUM_LENGTH),
            $parts === false, preg_match('/[\x00-\x20\x7f]/', $clientId) === 1, !isset($parts['host']) => 'it is no valid URL',
            ($parts['scheme'] ?? null) !== 'https' => 'it must use https',
            isset($parts['user']) || isset($parts['pass']) => 'it must not contain a username or password',
            isset($parts['fragment']) || str_contains($clientId, '#') => 'it must not contain a fragment',
            ($parts['path'] ?? '') === '' => 'it must contain a path, e.g. https://example.com/client.json',
            array_intersect(explode('/', rawurldecode($parts['path'])), ['.', '..']) !== [] => 'its path must not contain "." or ".." segments',
            default => null,
        };
        if ($problem !== null) {
            throw new InvalidClientMetadataDocument(sprintf('The client ID "%s" is no valid metadata document URL: %s', mb_strimwidth($clientId, 0, 300, '…'), $problem), 1792100103);
        }
    }

    /**
     * The client metadata (RFC 7591) this server uses from the document
     *
     * @return array{name: string, redirectUris: list<string>, grantTypes: list<string>, scope: string|null}
     * @throws InvalidClientMetadataDocument
     */
    private static function validate(string $clientId, string $body): array
    {
        try {
            $document = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new InvalidClientMetadataDocument(sprintf('it is no valid JSON (%s)', $exception->getMessage()), 1792100110);
        }
        if (!is_array($document) || array_is_list($document)) {
            throw new InvalidClientMetadataDocument('it must be a JSON object', 1792100111);
        }
        if (($document['client_id'] ?? null) !== $clientId) {
            throw new InvalidClientMetadataDocument(sprintf('its client_id must be its own URL "%s"', $clientId), 1792100112);
        }
        $name = $document['client_name'] ?? null;
        if (!is_string($name) || trim($name) === '') {
            throw new InvalidClientMetadataDocument('client_name is required', 1792100113);
        }
        $redirectUris = $document['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris) || array_filter($redirectUris, 'is_string') !== $redirectUris) {
            throw new InvalidClientMetadataDocument('redirect_uris must be a non-empty array of strings', 1792100114);
        }
        foreach ($redirectUris as $redirectUri) {
            try {
                ClientRegistration::assertAcceptableRedirectUri($redirectUri);
            } catch (\InvalidArgumentException $exception) {
                throw new InvalidClientMetadataDocument($exception->getMessage(), 1792100115);
            }
        }
        if (($document['token_endpoint_auth_method'] ?? 'none') !== 'none' || array_key_exists('client_secret', $document)) {
            throw new InvalidClientMetadataDocument('only public clients are supported: token_endpoint_auth_method must be "none" (or absent), private_key_jwt and client secrets are not supported', 1792100116);
        }
        $grantTypes = $document['grant_types'] ?? self::GRANT_TYPES;
        if (!is_array($grantTypes) || !in_array(OAuthClient::GRANT_AUTHORIZATION_CODE, $grantTypes, true) || array_diff($grantTypes, self::GRANT_TYPES) !== []) {
            throw new InvalidClientMetadataDocument(sprintf('grant_types must contain "%s" and may contain "%s" only', OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN), 1792100117);
        }
        if (($document['response_types'] ?? ['code']) !== ['code']) {
            throw new InvalidClientMetadataDocument('response_types must be ["code"]', 1792100118);
        }
        $scope = $document['scope'] ?? null;
        if ($scope !== null && !is_string($scope)) {
            throw new InvalidClientMetadataDocument('scope must be a string of space separated scopes', 1792100119);
        }
        return [
            'name' => mb_substr(trim($name), 0, 200),
            'redirectUris' => array_values(array_unique($redirectUris)),
            'grantTypes' => array_values(array_unique($grantTypes)),
            'scope' => $scope,
        ];
    }
}
