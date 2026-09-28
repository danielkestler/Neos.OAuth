<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain\Model;

use Doctrine\ORM\Mapping as ORM;
use Neos\Flow\Annotations as Flow;

/**
 * Tracks an issued access token, refresh token or authorization code, so that it can be revoked
 *
 * Only the token's identifier is stored, never the token itself
 */
#[Flow\Entity]
#[ORM\Table(indexes: [
    new ORM\Index(columns: ['clientidentifier']),
    new ORM\Index(columns: ['accountidentifier']),
    new ORM\Index(columns: ['expiresat']),
])]
class TokenRecord
{
    #[ORM\Column(unique: true)]
    protected string $identifier;

    #[ORM\Column(length: 20)]
    protected string $type;

    protected string $clientIdentifier;

    #[ORM\Column(nullable: true)]
    protected ?string $accountIdentifier;

    protected \DateTimeImmutable $expiresAt;

    protected bool $revoked = false;

    public function __construct(
        string $identifier,
        TokenType $type,
        string $clientIdentifier,
        ?string $accountIdentifier,
        \DateTimeImmutable $expiresAt,
    ) {
        $this->identifier = $identifier;
        $this->type = $type->value;
        $this->clientIdentifier = $clientIdentifier;
        $this->accountIdentifier = $accountIdentifier;
        $this->expiresAt = $expiresAt;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getType(): TokenType
    {
        return TokenType::from($this->type);
    }

    public function getClientIdentifier(): string
    {
        return $this->clientIdentifier;
    }

    public function getAccountIdentifier(): ?string
    {
        return $this->accountIdentifier;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function revoke(): void
    {
        $this->revoked = true;
    }
}
