<?php
declare(strict_types=1);

namespace Neos\OAuth\Command;

use Doctrine\ORM\EntityManagerInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use Neos\OAuth\Domain\Repository\TokenRecordRepository;
use Neos\OAuth\Domain\ClientDirectory;
use Neos\OAuth\Domain\ClientRegistration;
use Neos\OAuth\Domain\ScopeRegistry;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Neos\OAuth\Security\IssuerNotConfigured;
use Neos\OAuth\Security\ProtectedResources;
use Neos\OAuth\Infrastructure\League\KeyManager;

/**
 * Manage OAuth keys, clients and tokens
 */
class OAuthCommandController extends CommandController
{
    #[Flow\Inject]
    protected KeyManager $keyManager;

    #[Flow\Inject]
    protected ClientRegistration $clientRegistration;

    #[Flow\Inject]
    protected ClientDirectory $clientDirectory;

    #[Flow\Inject]
    protected ScopeRegistry $scopeRegistry;

    #[Flow\Inject]
    protected AuthorizationServerMetadata $authorizationServer;

    #[Flow\Inject]
    protected ProtectedResources $protectedResources;

    #[Flow\Inject]
    protected EntityManagerInterface $entityManager;

    #[Flow\Inject]
    protected OAuthClientRepository $clientRepository;

    #[Flow\Inject]
    protected TokenRecordRepository $tokenRecordRepository;

    #[Flow\Inject]
    protected PersistenceManagerInterface $persistenceManager;

    /**
     * Check the OAuth setup
     *
     * Checks the keys, the database tables, the issuer, the scopes, the clients and the protected resources, and tells
     * how to fix what's missing.
     */
    public function statusCommand(): void
    {
        $problems = 0;
        $report = function (bool $ok, string $message, string $fix = '') use (&$problems): void {
            $problems += $ok ? 0 : 1;
            $this->outputLine('%s %s', [$ok ? '<success>✔</success>' : '<error>✘</error>', $message]);
            if (!$ok && $fix !== '') {
                $this->outputLine('    → %s', [$fix]);
            }
        };

        $this->outputLine('<b>Keys</b>');
        if ($this->keyManager->keysAreConfigured()) {
            try {
                $this->keyManager->getPrivateKey();
                $this->keyManager->getPublicKey();
                $this->keyManager->getEncryptionKey();
                $report(true, 'Configured in Neos.OAuth.keys');
            } catch (\Throwable $exception) {
                $report(false, 'The configured keys are invalid: ' . $exception->getMessage(), 'Set Neos.OAuth.keys.privateKey, publicKey and encryptionKey, or none of them to use key files');
            }
        } else {
            $files = $this->keyManager->keyFiles();
            $existing = count(array_filter($files));
            if ($existing === count($files)) {
                $report(true, 'Key files in ' . dirname((string)array_key_first($files)));
            } elseif ($existing === 0) {
                $report(true, 'Key files will be generated on first use in ' . dirname((string)array_key_first($files)));
            } else {
                $report(false, 'Some key files are missing', 'Restore them, or replace all keys with ./flow oauth:generatekeys --force (invalidates all issued tokens)');
            }
        }

        $this->outputLine();
        $this->outputLine('<b>Database</b>');
        $tables = ['neos_oauth_domain_model_oauthclient', 'neos_oauth_domain_model_tokenrecord'];
        $report($this->entityManager->getConnection()->createSchemaManager()->tablesExist($tables), 'Tables ' . implode(', ', $tables), 'Run ./flow doctrine:migrate');

        $this->outputLine();
        $this->outputLine('<b>Issuer</b>');
        try {
            $report(true, sprintf('%s (from %s)', $this->authorizationServer->issuer(), $this->authorizationServer->issuerSource()));
        } catch (IssuerNotConfigured $exception) {
            $report(false, 'Unknown', 'Set Neos.OAuth.issuer to the base URI of the site, e.g. https://example.com, or add a domain to the default site');
        }

        $this->outputLine();
        $this->outputLine('<b>Scopes</b>');
        $scopes = $this->scopeRegistry->descriptions();
        $report($scopes !== [], $scopes !== [] ? implode(', ', array_keys($scopes)) : 'None registered', 'Packages that accept the tokens register their scopes in Neos.OAuth.scopes');

        $this->outputLine();
        $this->outputLine('<b>Clients</b>');
        foreach ($this->clientDirectory->declaredIdentifiers() as $identifier) {
            try {
                $client = $this->clientDirectory->declared($identifier);
                $report(true, sprintf('%s (configuration): %s', $identifier, implode(', ', $client->getRedirectUris()) ?: 'no redirect URIs'));
            } catch (\InvalidArgumentException | IssuerNotConfigured $exception) {
                $report(false, sprintf('%s (configuration): %s', $identifier, $exception->getMessage()), 'Fix Neos.OAuth.clients.' . $identifier);
            }
        }
        try {
            foreach ($this->clientDirectory->declaredIdentifiers() as $identifier) {
                if ($this->clientRepository->findOneByClientIdentifier($identifier) !== null) {
                    $report(false, sprintf('%s is also registered in the database, where it is ignored', $identifier), sprintf('Run ./flow oauth:removeclient %s', $identifier));
                }
            }
            $this->outputLine('  %d client(s) in the database, see ./flow oauth:listclients', [$this->clientRepository->countAll()]);
        } catch (\Throwable) {
            // the tables are missing, reported above
        }

        $this->outputLine();
        $this->outputLine('<b>Protected resources</b>');
        foreach (array_keys($this->protectedResources->all()) as $key) {
            try {
                $report(true, sprintf('%s: %s', $key, $this->protectedResources->metadataUrl($key)));
            } catch (\Throwable $exception) {
                $report(false, sprintf('%s: %s', $key, $exception->getMessage()));
            }
        }

        $this->outputLine();
        if ($problems > 0) {
            $this->outputLine('<error>%d problem(s) found.</error>', [$problems]);
            $this->quit(1);
        }
        $this->outputLine('<success>OAuth is set up.</success>');
    }

    /**
     * Generate the signing and encryption keys
     *
     * The keys are generated on first use, so this is only needed to create them in advance or to replace them.
     *
     * @param bool $force Replace existing keys. This invalidates all issued tokens
     */
    public function generateKeysCommand(bool $force = false): void
    {
        if ($this->keyManager->keysAreConfigured()) {
            $this->outputLine('<error>The keys are configured in Neos.OAuth.keys, not kept in files.</error>');
            $this->quit(1);
        }
        if ($this->keyManager->keyFilesExist() && !$force) {
            $this->outputLine('<error>Keys exist already.</error> Use --force to replace them, which invalidates all issued tokens.');
            $this->quit(1);
        }
        $this->keyManager->generateKeys();
        $this->outputLine('<success>Generated the OAuth keys.</success>');
    }

    /**
     * Register a client
     *
     * Public clients (the default) have no secret and use the authorization code grant with PKCE, e.g. single page or
     * native apps. Confidential clients get a secret, which is displayed once.
     *
     * The client_credentials grant is for machine to machine access without a user: its tokens act as the given account.
     *
     * @param string $name A name for the client, shown on the consent page
     * @param string|null $redirectUris Comma separated redirect URIs, required for the authorization_code grant
     * @param string $grantTypes Comma separated: authorization_code, refresh_token, client_credentials
     * @param string|null $scopes Comma separated scopes the client may request, defaults to all configured scopes
     * @param bool $confidential Create a confidential client with a secret
     * @param bool $firstParty Skip the consent page, only for applications you control
     * @param string|null $account The account identifier client_credentials tokens act as
     * @param string|null $identifier The client ID, generated if omitted
     */
    public function createClientCommand(
        string $name,
        ?string $redirectUris = null,
        string $grantTypes = 'authorization_code,refresh_token',
        ?string $scopes = null,
        bool $confidential = false,
        bool $firstParty = false,
        ?string $account = null,
        ?string $identifier = null,
    ): void {
        $identifier ??= bin2hex(random_bytes(16));
        try {
            $secret = $this->clientRegistration->register(
                $identifier,
                $name,
                self::split($redirectUris),
                self::split($grantTypes),
                $scopes !== null ? self::split($scopes) : null,
                $confidential,
                $firstParty,
                $account,
            );
        } catch (\InvalidArgumentException $exception) {
            $this->outputLine('<error>%s</error>', [$exception->getMessage()]);
            $this->quit(1);
        }

        $this->outputLine('<success>Created the client "%s".</success>', [$name]);
        $this->outputLine('Client ID:     %s', [$identifier]);
        if ($secret !== null) {
            $this->outputLine('Client secret: %s', [$secret]);
            $this->outputLine('<comment>The secret is not stored and cannot be displayed again.</comment>');
        }
    }

    /**
     * List the registered clients
     *
     * Shows each client's ID, type, grants, scopes and client_credentials account. Secrets are never shown.
     */
    public function listClientsCommand(): void
    {
        $rows = [];
        foreach ($this->clientDirectory->declaredIdentifiers() as $identifier) {
            try {
                $rows[] = self::clientRow($this->clientDirectory->declared($identifier), 'configuration');
            } catch (\InvalidArgumentException | IssuerNotConfigured $exception) {
                $rows[] = [$identifier, '<error>' . $exception->getMessage() . '</error>', 'configuration', '', '', ''];
            }
        }
        /** @var OAuthClient $client */
        foreach ($this->clientRepository->findAll() as $client) {
            $rows[] = self::clientRow($client, 'database');
        }
        if ($rows === []) {
            $this->outputLine('There are no clients.');
            return;
        }
        $this->output->outputTable($rows, ['Client ID', 'Name', 'Type', 'Grants', 'Scopes', 'Account']);
    }

    /**
     * @return list<string>
     */
    private static function clientRow(OAuthClient $client, string $source): array
    {
        return [
            $client->getIdentifier(),
            $client->getName(),
            ($client->isConfidential() ? 'confidential' : 'public') . ($client->isFirstParty() ? ', first party' : '') . "\n(" . $source . ')',
            implode("\n", $client->getGrantTypes()),
            implode("\n", $client->getScopes()),
            $client->getAccountIdentifier() ?? '',
        ];
    }

    /**
     * Remove a client
     *
     * Its tokens are rejected from then on.
     *
     * @param string $identifier The client ID
     */
    public function removeClientCommand(string $identifier): void
    {
        $client = $this->clientRepository->findOneByClientIdentifier($identifier);
        if ($client === null) {
            $this->outputLine(
                $this->clientDirectory->isDeclared($identifier)
                    ? '<error>The client "%s" is declared in Neos.OAuth.clients</error>, remove it from the configuration.'
                    : '<error>There is no client "%s".</error>',
                [$identifier],
            );
            $this->quit(1);
        }
        $this->revoke($identifier, null);
        $this->clientRepository->remove($client);
        $this->persistenceManager->persistAll();
        $this->outputLine('<success>Removed the client "%s".</success>', [$identifier]);
    }

    /**
     * Revoke tokens
     *
     * Revokes the active access tokens, refresh tokens and authorization codes of a client, an account, or both.
     *
     * @param string|null $client Only tokens of this client ID
     * @param string|null $account Only tokens of this account identifier
     */
    public function revokeTokensCommand(?string $client = null, ?string $account = null): void
    {
        if ($client === null && $account === null) {
            $this->outputLine('<error>Specify --client, --account or both.</error>');
            $this->quit(1);
        }
        $this->outputLine('Revoked %d token(s).', [$this->revoke($client, $account)]);
    }

    /**
     * Remove expired tokens
     *
     * Deletes the records of expired tokens, which are only kept to reject them. Run it regularly, e.g. daily.
     */
    public function pruneTokensCommand(): void
    {
        $this->outputLine('Removed %d expired token(s).', [$this->tokenRecordRepository->removeExpired(new \DateTimeImmutable())]);
    }

    private function revoke(?string $clientIdentifier, ?string $accountIdentifier): int
    {
        $records = $this->tokenRecordRepository->findActive($clientIdentifier, $accountIdentifier, new \DateTimeImmutable());
        foreach ($records as $record) {
            $record->revoke();
            $this->tokenRecordRepository->update($record);
        }
        $this->persistenceManager->persistAll();
        return count($records);
    }


    /**
     * @return list<string>
     */
    private static function split(?string $list): array
    {
        return array_values(array_filter(array_map('trim', explode(',', (string)$list)), static fn (string $item) => $item !== ''));
    }
}
