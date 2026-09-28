<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain\Model;

use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations as Flow;

/**
 * An application that may request tokens
 */
#[Flow\Entity]
class OAuthClient
{
    public const string GRANT_AUTHORIZATION_CODE = 'authorization_code';
    public const string GRANT_REFRESH_TOKEN = 'refresh_token';
    public const string GRANT_CLIENT_CREDENTIALS = 'client_credentials';
    public const array SUPPORTED_GRANTS = [self::GRANT_AUTHORIZATION_CODE, self::GRANT_REFRESH_TOKEN, self::GRANT_CLIENT_CREDENTIALS];

    #[ORM\Column(unique: true)]
    protected string $identifier;

    protected string $name;

    /**
     * Hash of the client secret, null for public clients
     */
    #[ORM\Column(nullable: true)]
    protected ?string $secretHash;

    /**
     * @var array
     */
    #[ORM\Column(type: 'json')]
    protected array $redirectUris;

    /**
     * @var array
     */
    #[ORM\Column(type: 'json')]
    protected array $grantTypes;

    /**
     * @var array
     */
    #[ORM\Column(type: 'json')]
    protected array $scopes;

    /**
     * First party clients are not asked for consent
     */
    protected bool $firstParty;

    /**
     * The account client_credentials tokens act as, null if the client may not use that grant
     */
    #[ORM\Column(nullable: true)]
    protected ?string $accountIdentifier;

    protected \DateTimeImmutable $createdAt;

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string> $scopes
     */
    public function __construct(
        string $identifier,
        string $name,
        ?string $secretHash,
        array $redirectUris,
        array $grantTypes,
        array $scopes,
        bool $firstParty,
        ?string $accountIdentifier,
    ) {
        $unsupportedGrants = array_diff($grantTypes, self::SUPPORTED_GRANTS);
        if ($unsupportedGrants !== []) {
            throw new \InvalidArgumentException(sprintf('Unsupported grant types: %s', implode(', ', $unsupportedGrants)), 1790100001);
        }
        if (in_array(self::GRANT_CLIENT_CREDENTIALS, $grantTypes, true) && ($secretHash === null || $accountIdentifier === null)) {
            throw new \InvalidArgumentException('The client_credentials grant requires a confidential client with an account', 1790100002);
        }
        if (in_array(self::GRANT_AUTHORIZATION_CODE, $grantTypes, true) && $redirectUris === []) {
            throw new \InvalidArgumentException('The authorization_code grant requires at least one redirect URI', 1790100003);
        }
        $this->identifier = $identifier;
        $this->name = $name;
        $this->secretHash = $secretHash;
        $this->redirectUris = array_values($redirectUris);
        $this->grantTypes = array_values($grantTypes);
        $this->scopes = array_values($scopes);
        $this->firstParty = $firstParty;
        $this->accountIdentifier = $accountIdentifier;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function isConfidential(): bool
    {
        return $this->secretHash !== null;
    }

    public function validateSecret(string $secret): bool
    {
        return $this->secretHash !== null && password_verify($secret, $this->secretHash);
    }

    /**
     * @return list<string>
     */
    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    /**
     * @return list<string>
     */
    public function getGrantTypes(): array
    {
        return $this->grantTypes;
    }

    public function allowsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /**
     * @return list<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function isFirstParty(): bool
    {
        return $this->firstParty;
    }

    public function getAccountIdentifier(): ?string
    {
        return $this->accountIdentifier;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }
}
